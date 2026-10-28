"""Multi-language CodeQL extraction, security analysis, and SARIF aggregation."""

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


# Extractor identifiers differ from the names of their query packs.
LANGUAGES = {
    "actions": ("actions", {".yml", ".yaml"}),
    "c-cpp": ("cpp", {".c", ".cpp", ".cc", ".cxx", ".c++", ".h", ".hpp", ".hh", ".hxx", ".h++"}),
    "csharp": ("csharp", {".cs", ".csproj", ".cshtml", ".xaml", ".sln", ".slnx"}),
    "go": ("go", {".go"}),
    "java-kotlin": ("java", {".java", ".kt", ".kts"}),
    "javascript-typescript": ("javascript", {".js", ".jsx", ".mjs", ".cjs", ".es", ".es6", ".ts", ".tsx", ".mts", ".cts", ".vue", ".html", ".htm", ".xhtml", ".xhtm", ".hbs", ".ejs", ".njk"}),
    "python": ("python", {".py"}),
    "ruby": ("ruby", {".rb", ".erb", ".gemspec"}),
    "rust": ("rust", {".rs"}),
    "swift": ("swift", {".swift"}),
}
IGNORED_DIRS = {".git", "node_modules", ".venv", "venv", "vendor", "target", "build", "dist", ".gradle", ".build"}


def detect_languages(repo_dir):
    """Return all detected extractors and whether Kotlin needs a build."""
    found = set()
    kotlin = False
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS and not Path(root, d).is_symlink())
        for filename in files:
            path = Path(root, filename)
            if path.is_symlink():
                continue
            relative = path.relative_to(repo_dir)
            suffix = path.suffix.lower()
            if ((relative.parts[:2] == (".github", "workflows") and len(relative.parts) == 3
                 and suffix in {".yml", ".yaml"}) or filename in {"action.yml", "action.yaml"}):
                found.add("actions")
            for language, (_, extensions) in LANGUAGES.items():
                if language != "actions" and suffix in extensions:
                    found.add(language)
            if suffix in {".kt", ".kts"}:
                kotlin = True
            if filename == "Gemfile":
                found.add("ruby")
            if filename == "Cargo.toml":
                found.add("rust")
    return [language for language in LANGUAGES if language in found], kotlin


def run_codeql(repo_dir, output_file, env=None, on_progress=None):
    """Return (fully_successful, log, errors); preserve successful SARIF runs on failure."""
    repo_dir = str(Path(repo_dir).resolve())
    output = Path(output_file).resolve()
    output.unlink(missing_ok=True)
    languages, kotlin = detect_languages(repo_dir)
    if not languages:
        return False, "", "CodeQL: no supported source files or GitHub Actions workflows found."

    # Build tools must not inherit API tokens configured for unrelated scanners.
    command_env = dict(os.environ if env is None else env)
    for key in ("GITHUB_TOKEN", "SNYK_TOKEN", "SEMGREP_APP_TOKEN"):
        command_env.pop(key, None)
    threads = command_env.get("CODEQL_THREADS", "2")
    ram = command_env.get("CODEQL_RAM", "2048")
    timeout = command_env.get("CODEQL_TIMEOUT", "0")
    if not all(value.isdecimal() and int(value) > 0 for value in (threads, ram)):
        return False, "", "CODEQL_THREADS and CODEQL_RAM must be positive integers."
    if not (timeout.isdecimal() and int(timeout) >= 0):
        return False, "", "CODEQL_TIMEOUT must be a non-negative integer (0 disables the timeout)."

    states = [{"language": language, "status": "pending", "error": ""} for language in languages]
    logs, errors, runs = [], [], []

    def notify():
        if on_progress:
            on_progress(copy.deepcopy(states))

    def execute(cmd, language, stage):
        logs.append(f"[{language}] {stage}")
        result = subprocess.run(cmd, cwd=repo_dir, env=command_env, capture_output=True,
                                text=True, timeout=None if int(timeout) == 0 else int(timeout))
        logs.append((result.stdout or "")[-6000:])
        logs.append((result.stderr or "")[-6000:])
        if result.returncode:
            detail = (result.stderr or result.stdout or f"exit code {result.returncode}").strip()
            raise RuntimeError(f"{stage}: {detail[-2000:]}")

    notify()
    for state in states:
        language = state["language"]
        pack, _ = LANGUAGES[language]
        database = str(output.parent / f"codeql-db-{language}")
        report = output.parent / f"codeql-{language}.sarif"
        try:
            report.unlink(missing_ok=True)
            if language == "swift" and sys.platform != "darwin":
                raise RuntimeError("Swift analysis requires a macOS host with Xcode/Swift and the macOS CodeQL bundle. Import a SARIF report generated there.")
            mode = "autobuild" if language in {"go", "swift"} or (language == "java-kotlin" and kotlin) else "none"
            required = {"go": ("go",), "rust": ("rustup", "cargo"), "swift": ("swift", "xcodebuild")}.get(language, ())
            if language == "java-kotlin" and kotlin:
                required = ("java",)
            missing = [tool for tool in required if not shutil.which(tool, path=command_env.get("PATH"))]
            if missing:
                raise RuntimeError("Missing build tools: " + ", ".join(missing))
            state["status"] = "creating"
            state["build_mode"] = mode
            notify()
            execute(["codeql", "database", "create", database, f"--source-root={repo_dir}",
                     f"--language={language}", f"--build-mode={mode}", f"--threads={threads}",
                     f"--ram={ram}", "--overwrite"], language, "database creation")
            state["status"] = "analyzing"
            notify()
            suite = f"codeql/{pack}-queries:codeql-suites/{pack}-security-extended.qls"
            execute(["codeql", "database", "analyze", database, suite, "--format=sarifv2.1.0",
                     f"--output={report}", f"--sarif-category={language}", "--sarif-add-query-help",
                     f"--threads={threads}", f"--ram={ram}"], language, "security analysis")
            with report.open() as stream:
                sarif = json.load(stream)
            if (not isinstance(sarif, dict) or sarif.get("version") != "2.1.0"
                    or not isinstance(sarif.get("runs"), list) or not sarif["runs"]
                    or any(not isinstance(run, dict) or not isinstance(run.get("tool"), dict)
                           for run in sarif["runs"])):
                raise ValueError("CodeQL produced an invalid or empty SARIF report")
            runs.extend(sarif["runs"])
            state["status"] = "completed"
        except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
            stage = "security analysis" if state["status"] == "analyzing" else "database creation"
            state["status"] = "failed"
            detail = f"Timed out after {timeout}s during {stage}" if isinstance(exc, subprocess.TimeoutExpired) else str(exc)
            state["error"] = detail
            errors.append(f"[{language}] {detail}")
        finally:
            # Databases are large; retain reports until aggregation, not databases.
            shutil.rmtree(database, ignore_errors=True)
        notify()

    if runs:
        with output.open("w") as stream:
            json.dump({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": runs}, stream)
    summary = "\n".join(f"[{state['language']}] {state['status']}" for state in states)
    return not errors, summary + "\n" + "\n".join(logs), "\n".join(errors)
