import fcntl
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from codeql_runner import run_codeql
from crypto import decrypt
from db import projects_col, scans_col, settings_col
from helpers import insert_findings_for_project
from parsers import detect_format, parse_gitleaks, parse_sarif, parse_trufflehog

SCANNERS = {
    "semgrep":    {"cmd": "semgrep", "output_format": "sarif",      "description": "SAST scanner for 30+ languages. Uses 'semgrep ci' with Semgrep Cloud rules when token is set, otherwise falls back to 'semgrep scan'.", "requires_token": None},
    "snyk":       {"cmd": "snyk", "label": "Snyk dependencies", "output_format": "sarif", "description": "Snyk Open Source: checks dependencies for known vulnerabilities and license issues across supported projects. Requires a Snyk token (configure in Settings).", "requires_token": "snyk_token"},
    "snyk_code":  {"cmd": "snyk", "label": "Snyk Code", "output_format": "sarif", "description": "Checks source code for security vulnerabilities using Snyk Code. Requires a Snyk token with Snyk Code access (configure in Settings).", "requires_token": "snyk_token"},
    "codeql":     {"cmd": "codeql", "output_format": "sarif",       "description": "GitHub CodeQL: detects all supported languages and runs extended security queries. Swift requires macOS. Results from successful languages are kept if another language fails."},
    "trufflehog": {"cmd": "trufflehog", "output_format": "trufflehog", "description": "Scans for leaked secrets, API keys, and credentials in git history."},
    "gitleaks":   {"cmd": "gitleaks", "output_format": "gitleaks",  "description": "Fast secret scanner using regex and entropy detection."},
}

SETTINGS_KEYS = ["snyk_token", "github_token", "semgrep_token"]

SCAN_REPO_BASE = "/tmp/scan_repos"

# File lock serializing `semgrep ci` runs so a single process installs the
# Semgrep Pro Engine; concurrent runs race on the fixed .tmp_download path.
SEMGREP_CI_LOCK = "/tmp/semgrep_ci.lock"

scan_executor = ThreadPoolExecutor(max_workers=2)


def _validate_repo_url(url):
    """Validate that a repo URL is a safe public HTTP(S) Git URL."""
    if not url or not isinstance(url, str):
        return False
    url = url.strip()
    if not re.match(r'^https?://', url, re.IGNORECASE):
        return False

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except Exception:
        return False

    if not hostname:
        return False

    # Resolve hostname to IP and block non-public ranges (private, loopback,
    # link-local, multicast, reserved). is_global keeps NAT64/DNS64 networks
    # (64:ff9b::/96) working while still rejecting internal addresses.
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for _, _, _, _, sockaddr in addr_info:
            ip = ipaddress.ip_address(sockaddr[0])
            if not ip.is_global:
                return False
    except (socket.gaierror, ValueError):
        return False

    return True


def _update_scan(scan_id, **fields):
    """Update scan document fields."""
    scans_col.update_one({"_id": scan_id}, {"$set": fields})


def get_settings_dict():
    """Return a dict of all settings {key: decrypted_value}."""
    result = {}
    for doc in settings_col.find({"key": {"$in": SETTINGS_KEYS}}):
        raw = doc.get("value", "")
        result[doc["key"]] = decrypt(raw) or raw if raw else ""
    return result


def _get_scanner_env(settings=None):
    """Build environment dict with tokens from settings collection."""
    if settings is None:
        settings = get_settings_dict()
    env = os.environ.copy()
    if settings.get("snyk_token"):
        # The CLI authenticates directly from SNYK_TOKEN. Do not run network
        # authentication while preparing unrelated scans such as CodeQL.
        env["SNYK_TOKEN"] = settings["snyk_token"]
    if settings.get("github_token"):
        env["GITHUB_TOKEN"] = settings["github_token"]
    return env


def _run_scanner_command(tool, repo_dir, output_file, env=None, custom_configs=None, on_progress=None):
    """Run the appropriate scanner command and return (success, stdout, stderr)."""
    timeout = 1800
    run_kw = dict(capture_output=True, text=True, timeout=timeout)
    if env is not None:
        run_kw["env"] = env

    try:
        if tool == "semgrep":
            extra_configs = [f"--config={p}" for p in (custom_configs or [])]
            semgrep_token = get_settings_dict().get("semgrep_token")
            # `semgrep ci` rejects extra --config flags while logged in, so fall
            # back to `semgrep scan` whenever custom rules are provided.
            use_ci = bool(semgrep_token) and not extra_configs
            if use_ci:
                ci_env = dict(env or os.environ.copy())
                ci_env["SEMGREP_APP_TOKEN"] = semgrep_token
                ci_kw = dict(run_kw)
                ci_kw["env"] = ci_env
                ci_kw["cwd"] = repo_dir
                cmd = ["semgrep", "ci", "--no-suppress-errors", "--sarif",
                       f"--sarif-output={output_file}", "--timeout=300"]
                # Serialize `semgrep ci`: the first run downloads and installs
                # the Pro Engine to a fixed path; concurrent runs in the same
                # container race on that file (corrupting it or removing it
                # under each other). A file lock lets one process install it,
                # then later runs detect it via check_if_installed() and skip.
                with open(SEMGREP_CI_LOCK, "w") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    try:
                        result = subprocess.run(cmd, **ci_kw)
                    finally:
                        fcntl.flock(lock, fcntl.LOCK_UN)
                if any(message in (result.stderr or "").lower()
                       for message in ("invalid api key", "api token not valid", "http 401")):
                    return False, "", (
                        "Semgrep rejected the configured API token. Update the Semgrep token in Settings "
                        "and retry, or remove it to use the default public rules.")
            if not use_ci:
                subprocess.run(["semgrep", "logout"], capture_output=True, text=True, timeout=10)
                cmd = ["semgrep", "scan", "--config=p/default"] + extra_configs + [
                       "--metrics=off", "--timeout=300", "--sarif", f"--sarif-output={output_file}", repo_dir]
                result = subprocess.run(cmd, **run_kw)
            return result.returncode in (0, 1), result.stdout, result.stderr

        elif tool == "snyk":
            cmd = ["snyk", "test", "--all-projects", f"--sarif-file-output={output_file}"]
            result = subprocess.run(cmd, cwd=repo_dir, **run_kw)
            return result.returncode in (0, 1), result.stdout, result.stderr

        elif tool == "snyk_code":
            cmd = ["snyk", "code", "test", f"--sarif-file-output={output_file}", repo_dir]
            result = subprocess.run(cmd, **run_kw)
            return result.returncode in (0, 1), result.stdout, result.stderr

        elif tool == "codeql":
            return run_codeql(repo_dir, output_file, env=env, on_progress=on_progress)

        elif tool == "trufflehog":
            cmd = ["trufflehog", "git", Path(repo_dir).resolve().as_uri(), "--json"]
            result = subprocess.run(cmd, **run_kw)
            with open(output_file, "w") as f:
                f.write(result.stdout)
            return result.returncode == 0, result.stdout, result.stderr

        elif tool == "gitleaks":
            cmd = ["gitleaks", "detect", f"--source={repo_dir}", "--log-opts=--all", "--report-format=json", f"--report-path={output_file}"]
            result = subprocess.run(cmd, **run_kw)
            return result.returncode in (0, 1), result.stdout, result.stderr

        else:
            return False, "", f"Unknown scanner: {tool}"

    except FileNotFoundError:
        return False, "", f"Scanner binary '{tool}' not found in PATH. Is it installed?"


def _repo_name_from_url(url):
    """Extract a safe directory name from a git URL."""
    path = re.sub(r'^https?://', '', url).rstrip('/')
    path = re.sub(r'\.git$', '', path)
    parts = path.split('/')
    name = '_'.join(parts[-2:]) if len(parts) >= 2 else parts[-1]
    name = re.sub(r'[^a-zA-Z0-9_\-]', '_', name)
    return name or "repo"


def _clone_repository(repo_url, repo_dir, branch, env, tmpdir):
    """Provide the configured PAT only to GitHub HTTPS credential requests."""
    clone_env = dict(env)
    clone_env["GIT_TERMINAL_PROMPT"] = "0"
    cmd = ["git"]
    parsed = urlparse(repo_url)
    if (parsed.scheme == "https" and parsed.hostname == "github.com"
            and parsed.port in (None, 443) and clone_env.get("GITHUB_TOKEN")):
        helper_path = os.path.join(tmpdir, "git-credential-github")
        # No token is written to disk, command arguments, or the remote URL.
        with open(helper_path, "w") as helper:
            helper.write(
                f"#!{sys.executable}\n"
                "import os, sys\n"
                "if len(sys.argv) != 2 or sys.argv[1] != 'get':\n"
                "    sys.exit(0)\n"
                "fields = dict(line.rstrip('\\n').split('=', 1) for line in sys.stdin if '=' in line)\n"
                "if fields.get('protocol') == 'https' and fields.get('host') in ('github.com', 'github.com:443'):\n"
                "    print('username=x-access-token')\n"
                "    print('password=' + os.environ['GITHUB_TOKEN'])\n"
                "    print()\n"
            )
        os.chmod(helper_path, 0o600)
        # The repository tmpfs is mounted noexec. Let Python read the helper
        # rather than asking the kernel to execute a file on that mount.
        helper_command = f"!{shlex.quote(sys.executable)} {shlex.quote(helper_path)}"
        cmd.extend(["-c", "credential.helper=", "-c", f"credential.helper={helper_command}"])
    else:
        clone_env.pop("GITHUB_TOKEN", None)
    cmd.append("clone")
    if branch:
        cmd.extend(["--branch", branch])
    cmd.extend([repo_url, repo_dir])
    return subprocess.run(cmd, capture_output=True, text=True, timeout=1800, env=clone_env)


def run_scan(scan_id):
    """Execute a scan in a background thread."""
    scan = scans_col.find_one({"_id": scan_id})
    if not scan:
        return

    tool = scan["tool"]
    repo_url = scan["repo_url"]
    branch = scan.get("branch")
    project_id = scan["project_id"]
    scanner_info = SCANNERS.get(tool)

    tmpdir = None
    try:
        settings = get_settings_dict()
        scanner_env = _get_scanner_env(settings)

        _update_scan(scan_id, status="cloning")
        repo_name = _repo_name_from_url(repo_url)
        tmpdir = os.path.join(SCAN_REPO_BASE, f"{repo_name}_{scan_id}")
        os.makedirs(tmpdir, exist_ok=True)
        repo_dir = os.path.join(tmpdir, repo_name)

        clone_result = _clone_repository(repo_url, repo_dir, branch, scanner_env, tmpdir)
        if clone_result.returncode != 0:
            _update_scan(scan_id, status="failed",
                         error=f"Git clone failed: {clone_result.stderr[:2000]}",
                         completed_at=datetime.now(timezone.utc))
            return

        _update_scan(scan_id, status="running")
        output_file = os.path.join(tmpdir, "output.json")

        custom_configs = []
        if tool == "semgrep":
            from db import semgrep_rules_col
            custom_rules = list(semgrep_rules_col.find())
            if custom_rules:
                rules_dir = os.path.join(tmpdir, "custom_rules")
                os.makedirs(rules_dir, exist_ok=True)
                for i, rule in enumerate(custom_rules):
                    rule_path = os.path.join(rules_dir, f"rule_{i}.yaml")
                    with open(rule_path, "w") as rf:
                        rf.write(rule["content"])
                    custom_configs.append(rule_path)

        success, stdout, stderr = _run_scanner_command(
            tool, repo_dir, output_file, env=scanner_env, custom_configs=custom_configs,
            on_progress=lambda states: _update_scan(scan_id, codeql_languages=states),
        )

        log_text = (stdout + "\n" + stderr)[:10000]
        _update_scan(scan_id, log=log_text)

        partial = tool == "codeql" and not success and os.path.exists(output_file)
        if not success and not partial:
            error_lines = [l for l in stderr.strip().splitlines()
                           if not l.startswith("METRICS:") and "semgrep.dev/docs/metrics" not in l
                           and l.strip()]
            error_detail = "\n".join(error_lines) or stdout.strip() or "No output (scanner may have crashed)"
            _update_scan(scan_id, status="failed",
                         error=f"Scanner failed: {error_detail[:2000]}",
                         completed_at=datetime.now(timezone.utc))
            return

        _update_scan(scan_id, status="parsing")

        output_format = scanner_info["output_format"]
        findings = []

        if output_format == "sarif" and (not os.path.isfile(output_file) or os.path.getsize(output_file) == 0):
            _update_scan(scan_id, status="failed",
                         error="Scanner did not produce a SARIF report. Check the scanner log for authentication or configuration errors.",
                         completed_at=datetime.now(timezone.utc))
            return

        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, "r") as f:
                raw_text = f.read()

            if output_format == "sarif":
                try:
                    sarif_data = json.loads(raw_text)
                    if (not isinstance(sarif_data, dict)
                            or not isinstance(sarif_data.get("runs"), list) or not sarif_data["runs"]
                            or any(not isinstance(run, dict) or not isinstance(run.get("tool"), dict)
                                   or not isinstance(run.get("results", []), list)
                                   for run in sarif_data["runs"])):
                        raise ValueError("Invalid SARIF report structure or missing tool runs")
                    if any(invocation.get("executionSuccessful") is False
                           for run in sarif_data["runs"] for invocation in run.get("invocations", [])):
                        raise ValueError("Scanner reported an unsuccessful analysis in its SARIF report")
                    findings = parse_sarif(sarif_data)
                except (ValueError, TypeError, AttributeError) as e:
                    _update_scan(scan_id, status="failed",
                                 error=f"Failed to parse SARIF output: {str(e)}",
                                 completed_at=datetime.now(timezone.utc))
                    return
            elif output_format == "trufflehog":
                fmt, parsed = detect_format(raw_text)
                if fmt == "trufflehog":
                    findings = parse_trufflehog(parsed)
                else:
                    _update_scan(scan_id, status="failed",
                                 error=f"Failed to parse TruffleHog output (detected as '{fmt}')",
                                 completed_at=datetime.now(timezone.utc))
                    return
            elif output_format == "gitleaks":
                fmt, parsed = detect_format(raw_text)
                if fmt == "gitleaks":
                    findings = parse_gitleaks(parsed)
                else:
                    _update_scan(scan_id, status="failed",
                                 error=f"Failed to parse gitleaks output (detected as '{fmt}')",
                                 completed_at=datetime.now(timezone.utc))
                    return

        for finding in findings:
            finding["scan_id"] = str(scan_id)
        parsed_repo = urlparse(repo_url)
        repo_scope = (parsed_repo.netloc.lower() + parsed_repo.path.rstrip("/").removesuffix(".git")
                      + "@" + (branch or "HEAD"))
        inserted, duplicates = insert_findings_for_project(
            project_id, findings, output_format, f"scan-{tool}", correlate=True,
            repo_scope=repo_scope, repo_dir=repo_dir)

        completed = datetime.now(timezone.utc)
        started = scan.get("started_at")
        if started and started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        duration = (completed - started).total_seconds() if started else 0

        _update_scan(scan_id,
                     status="partial" if partial else "completed",
                     error=stderr[:6000] if partial else "",
                     completed_at=completed,
                     duration_seconds=round(duration, 1),
                     findings_count=inserted,
                     observations_count=len(findings),
                     duplicates_count=duplicates)

    except subprocess.TimeoutExpired:
        _update_scan(scan_id, status="failed",
                     error="Scanner timed out (30 min limit)",
                     completed_at=datetime.now(timezone.utc))
    except Exception as e:
        _update_scan(scan_id, status="failed",
                     error=str(e)[:2000],
                     completed_at=datetime.now(timezone.utc))
    finally:
        if tmpdir and os.path.exists(tmpdir):
            shutil.rmtree(tmpdir, ignore_errors=True)
