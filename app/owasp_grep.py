#!/usr/bin/env python3
"""
OWASP sink grep — scanne une base de code à la recherche de sinks OWASP
et émet un fichier SARIF 2.1.0 importable par Sarif2Web (POST /api/upload).

Usage :
  python3 owasp_grep.py <target-dir> [-o out.sarif] [--project-id ID] [--upload] [--url URL]

Le script ne fait QUE du grep : il signale les sinks (sources potentielles de
faille) pour revue manuelle. Il ne conclut pas à une vulnérabilité — chaque
résultat doit être validé en croisant avec `$request->` / l'origine des données.
"""

import argparse
import json
import os
import re
import subprocess
import sys

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
TOOL_NAME = "owasp-sink-grep"

SCAN_EXTENSIONS = (".php", ".js", ".ts", ".vue", ".html", ".twig", ".py", ".rb")
EXCLUDE_DIRS = {
    "vendor", "node_modules", ".git", "public/build", "storage",
    "bootstrap/cache", "dist", "coverage", ".idea", ".vscode",
}

# ---------------------------------------------------------------------------
# Définition des sinks. Chaque règle : id, nom, sévérité, CWE, OWASP, catégorie,
# message, et liste de motifs regex (recherchés ligne par ligne).
# ---------------------------------------------------------------------------
SINKS = [
    # A. XSS
    dict(
        id="OWASP-XSS-BLADE-RAW", name="Blade raw output {!! !!}", level="error",
        cwe="CWE-79", owasp="OWASP-A03-Injection", category="XSS",
        patterns=[r"\{!!"],
        message="Sortie Blade brute {!! !!} — XSS si la valeur interpolée est contrôlée par l'utilisateur.",
    ),
    dict(
        id="OWASP-XSS-JS-HTML-SINK", name="jQuery/JS HTML sink", level="error",
        cwe="CWE-79", owasp="OWASP-A03-Injection", category="XSS",
        patterns=[r"\.html\(", r"\.append\(", r"\.prepend\(", r"innerHTML"],
        message="Sink HTML JS (.html/.append/.prepend/innerHTML) — DOM XSS si l'argument est contrôlé.",
    ),
    dict(
        id="OWASP-XSS-HTML-HELPER", name="HTML/markdown helper", level="warning",
        cwe="CWE-79", owasp="OWASP-A03-Injection", category="XSS",
        patterns=[r"->addHtml\(", r"Parsedown", r"->text\("],
        message="Helper HTML/Markdown — XSS si le contenu (ex. addHtml) n'est pas échappé/sanitisé.",
    ),

    # B. Mass assignment / privesc
    dict(
        id="OWASP-MASS-ASSIGNMENT", name="Mass assignment", level="error",
        cwe="CWE-915", owasp="OWASP-A04-Insecure-Design", category="Mass assignment",
        patterns=[
            r"->create\(\s*\$request->all\(", r"->update\(\s*\$request->all\(",
            r"->fill\(\s*\$request->", r"->forceFill\(",
        ],
        message="Mass assignment — des champs non validés de $request sont injectés dans le modèle.",
    ),
    dict(
        id="OWASP-UNVALIDATED-INPUT", name="$request->all()/only()/except()", level="warning",
        cwe="CWE-20", owasp="OWASP-A04-Insecure-Design", category="Mass assignment",
        patterns=[r"\$request->all\(\)", r"\$request->only\(", r"\$request->except\("],
        message="Récupération de champs $request sans validation stricte — vérifier allowlist/validation.",
    ),

    # C. IDOR / contrôle d'accès
    dict(
        id="OWASP-IDOR-FIND", name="find/findOrFail on request id", level="error",
        cwe="CWE-639", owasp="OWASP-A01-Broken-Access-Control", category="IDOR",
        patterns=[r"->find\(\s*\$request->", r"->findOrFail\(\s*\$request->", r"->firstOrFail\("],
        message="IDOR potentiel — recherche d'un enregistrement par id contrôlé sans vérifier l'appartenance/ownership.",
    ),
    dict(
        id="OWASP-AUTH-LOGIN-BYPASS", name="Programmatic login", level="error",
        cwe="CWE-287", owasp="OWASP-A07-Identification-Auth", category="Auth",
        patterns=[r"loginUsingId\(", r"Auth::login\("],
        message="Login programmatique — vérifier que l'id/identité n'est pas contrôlable par l'utilisateur.",
    ),

    # D. Injection SQL
    dict(
        id="OWASP-SQLI-RAW", name="Raw SQL builder", level="error",
        cwe="CWE-89", owasp="OWASP-A03-Injection", category="SQLi",
        patterns=[
            r"DB::raw\(", r"->whereRaw\(", r"->selectRaw\(", r"->orderByRaw\(",
            r"->groupByRaw\(", r"->havingRaw\(",
        ],
        message="Construction SQL brute — SQLi si une entrée utilisateur est concaténée sans binding.",
    ),
    dict(
        id="OWASP-SQLI-ORDERBY", name="orderBy on user value", level="error",
        cwe="CWE-89", owasp="OWASP-A03-Injection", category="SQLi",
        patterns=[r"->orderBy\(\s*\$request->", r"->orderBy\(\s*\$"],
        message="orderBy sur valeur contrôlée — injection de nom de colonne (échappement/binding inefficace sur les colonnes).",
    ),

    # E. RCE / désérialisation
    dict(
        id="OWASP-RCE", name="Command/code execution sink", level="error",
        cwe="CWE-78", owasp="OWASP-A03-Injection", category="RCE",
        patterns=[
            r"shell_exec\(", r"\bexec\(", r"\bsystem\(", r"passthru\(",
            r"proc_open\(", r"\bpopen\(", r"\beval\(", r"\bassert\(",
        ],
        message="Sink d'exécution de commande/code — RCE si une entrée utilisateur atteint la commande.",
    ),
    dict(
        id="OWASP-DESERIALIZE", name="unserialize", level="error",
        cwe="CWE-502", owasp="OWASP-A08-Software-and-Data-Integrity-Failures", category="Deserialization",
        patterns=[r"unserialize\("],
        message="unserialize() — object injection si la donnée est contrôlée par l'utilisateur.",
    ),

    # F. SSRF
    dict(
        id="OWASP-SSRF", name="SSRF sink", level="error",
        cwe="CWE-918", owasp="OWASP-A10-SSRF", category="SSRF",
        patterns=[r"curl_init\(", r"file_get_contents\(", r"Http::get\(", r"Http::post\(", r"GuzzleHttp"],
        message="Sink SSRF — vérifier que l'URL/hôte n'est pas contrôlé par l'utilisateur (et sinon, que le SSRF-guard est appliqué).",
    ),

    # G. Path traversal / upload
    dict(
        id="OWASP-PATH-TRAVERSAL", name="File write/store sink", level="warning",
        cwe="CWE-22", owasp="OWASP-A01-Broken-Access-Control", category="Path traversal",
        patterns=[
            r"->store\(", r"->move\(", r"->file\(", r"file_put_contents\(",
            r"fwrite\(", r"->extractTo\(",
        ],
        message="Écriture/déplacement de fichier — path traversal si le chemin/le nom provient de l'utilisateur.",
    ),
    dict(
        id="OWASP-FILE-DELETE", name="unlink", level="warning",
        cwe="CWE-22", owasp="OWASP-A01-Broken-Access-Control", category="Path traversal",
        patterns=[r"unlink\("],
        message="Suppression de fichier — path traversal si le chemin est contrôlé.",
    ),

    # H. Open redirect
    dict(
        id="OWASP-OPEN-REDIRECT", name="Open redirect", level="warning",
        cwe="CWE-601", owasp="OWASP-A01-Broken-Access-Control", category="Open redirect",
        patterns=[r"redirect\(\s*\$request->", r"->away\("],
        message="Redirection vers une valeur contrôlée — open redirect possible.",
    ),

    # I. Protections désactivées
    dict(
        id="OWASP-DISABLED-PROTECTION", name="withoutMiddleware", level="warning",
        cwe="CWE-693", owasp="OWASP-A05-Security-Misconfiguration", category="Misconfiguration",
        patterns=[r"->withoutMiddleware\("],
        message="Middleware désactivé (CSRF/auth) — vérifier la justification.",
    ),
]


def _compile():
    compiled = []
    for s in SINKS:
        s = dict(s)
        s["regexes"] = [re.compile(p) for p in s["patterns"]]
        compiled.append(s)
    return compiled


def scan_tree(target_dir):
    """Parcourt l'arborescence et renvoie la liste des matchs."""
    compiled = _compile()
    matches = []

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for name in files:
            if not name.endswith(SCAN_EXTENSIONS):
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, target_dir)

            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            except OSError:
                continue

            for lineno, line in enumerate(lines, start=1):
                line_s = line.rstrip("\n")
                stripped = line_s.strip()
                if not stripped:
                    continue
                for rule in compiled:
                    if any(rx.search(line_s) for rx in rule["regexes"]):
                        matches.append((rule, rel, lineno, stripped))

    return matches


def build_sarif(matches, target_name):
    """Construit le SARIF 2.1.0 à partir des matchs."""
    rules = {}
    results = []

    for rule, rel, lineno, snippet in matches:
        if rule["id"] not in rules:
            rules[rule["id"]] = {
                "id": rule["id"],
                "name": rule["name"],
                "shortDescription": {"text": rule["name"]},
                "fullDescription": {"text": rule["message"]},
                "defaultConfiguration": {"level": rule["level"]},
                "properties": {"tags": [rule["cwe"], rule["owasp"], rule["category"]]},
            }

        results.append({
            "ruleId": rule["id"],
            "level": rule["level"],
            "message": {"text": rule["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": rel},
                    "region": {"startLine": lineno, "snippet": {"text": snippet[:200]}},
                }
            }],
        })

    # Tri stable : par uri puis ligne
    results.sort(key=lambda r: (r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                                r["locations"][0]["physicalLocation"]["region"]["startLine"]))

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "rules": list(rules.values())}},
            "results": results,
        }],
    }


def upload_to_sarif2web(sarif_path, project_id, base_url):
    """Envoie le SARIF à Sarif2Web via POST /api/upload (multipart)."""
    url = base_url.rstrip("/") + "/api/upload"
    cmd = [
        "curl", "-s", "-X", "POST",
        "-F", f"file=@{sarif_path}",
        "-F", f"project_id={project_id}",
        url,
    ]
    out = subprocess.run(cmd, capture_output=True, text=True)
    sys.stdout.write(out.stdout)
    if out.returncode != 0:
        sys.stderr.write(out.stderr)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target_dir", help="Répertoire racine à scanner")
    parser.add_argument("-o", "--output", help="Fichier SARIF de sortie (défaut : <target>-owasp.sarif)")
    parser.add_argument("--project-id", help="ID du projet Sarif2Web (requis si --upload)")
    parser.add_argument("--upload", action="store_true", help="Uploader le SARIF vers Sarif2Web après génération")
    parser.add_argument("--url", default="http://localhost:9090", help="URL de base Sarif2Web (défaut : http://localhost:9090)")
    args = parser.parse_args(argv)

    target_dir = os.path.abspath(args.target_dir)
    if not os.path.isdir(target_dir):
        parser.error(f"répertoire introuvable : {target_dir}")

    target_name = os.path.basename(target_dir.rstrip("/"))
    output = args.output or f"{target_name}-owasp.sarif"

    matches = scan_tree(target_dir)
    sarif = build_sarif(matches, target_name)

    with open(output, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)

    # Bilan console
    counts = {}
    for rule, _, _, _ in matches:
        counts[rule["id"]] = counts.get(rule["id"], 0) + 1
    print(f"Sinks trouvés : {len(matches)} (SARIF écrit dans {output})")
    for rid, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {n:4d}  {rid}")

    if args.upload:
        if not args.project_id:
            parser.error("--upload requiert --project-id")
        upload_to_sarif2web(output, args.project_id, args.url)

    return 0


if __name__ == "__main__":
    sys.exit(main())
