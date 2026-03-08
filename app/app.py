import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from bson import ObjectId
from flask import Flask, Response, jsonify, render_template, request
from pymongo import MongoClient

app = Flask(__name__)

client = MongoClient(os.environ.get("MONGO_URI", "mongodb://localhost:27017/sarif_manager"))
db = client.get_default_database()
projects_col = db["projects"]
findings_col = db["findings"]
scans_col = db["scans"]
settings_col = db["settings"]

STATUSES = ["new", "confirmed", "false_positive", "mitigated", "accepted_risk"]

# Ensure index for fast per-project duplicate lookups
findings_col.create_index([("project_id", 1), ("dedup_hash", 1)])

# Thread pool for async scan execution
scan_executor = ThreadPoolExecutor(max_workers=2)

SCANNERS = {
    "semgrep":    {"cmd": "semgrep", "output_format": "sarif",      "description": "SAST scanner for 30+ languages. Uses 'semgrep ci' with Semgrep Cloud rules when token is set, otherwise falls back to 'semgrep scan'.", "requires_token": None},
    "snyk":       {"cmd": "snyk", "output_format": "sarif",         "description": "Snyk Code — finds vulnerabilities using semantic analysis. Requires a Snyk token (configure in Settings).", "requires_token": "snyk_token"},
    "codeql":     {"cmd": "codeql", "output_format": "sarif",       "description": "GitHub CodeQL — deep semantic code analysis engine."},
    "trufflehog": {"cmd": "trufflehog", "output_format": "trufflehog", "description": "Scans for leaked secrets, API keys, and credentials in git history."},
    "gitleaks":   {"cmd": "gitleaks", "output_format": "gitleaks",  "description": "Fast secret scanner using regex and entropy detection."},
}

SCAN_REPO_BASE = "/tmp/scan_repos"


def compute_dedup_hash(finding):
    """Compute a deduplication hash for a finding based on its identity fields.

    Two findings are considered duplicates only if they share the exact same
    rule, file, line range, and code snippet — i.e. the same vulnerability at
    the same location.
    """
    key = (
        f"{finding.get('rule_id', '')}:"
        f"{finding.get('file', '')}:"
        f"{finding.get('start_line', 0)}:"
        f"{finding.get('end_line', 0)}:"
        f"{finding.get('snippet', '')}"
    )
    return hashlib.sha256(key.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def detect_format(raw_text):
    """Detect if input is SARIF, TruffleHog JSONL, gitleaks JSON, or unknown."""
    stripped = raw_text.strip()
    # SARIF is a single JSON object with "$schema" or "runs"
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            if "runs" in data or "sarif" in data.get("$schema", "").lower():
                return "sarif", data
        except json.JSONDecodeError:
            pass
    # gitleaks JSON is a top-level array with RuleID + Fingerprint
    if stripped.startswith("["):
        try:
            data = json.loads(stripped)
            if isinstance(data, list) and data and "RuleID" in data[0] and "Fingerprint" in data[0]:
                return "gitleaks", data
        except json.JSONDecodeError:
            pass
    # TruffleHog outputs one JSON object per line (JSONL)
    lines = [l for l in stripped.splitlines() if l.strip()]
    if lines:
        try:
            first = json.loads(lines[0])
            if "SourceMetadata" in first and "DetectorName" in first:
                results = [first]
                for line in lines[1:]:
                    if line.strip():
                        results.append(json.loads(line))
                return "trufflehog", results
        except (json.JSONDecodeError, KeyError):
            pass
    # Fallback: try as plain JSON
    try:
        return "sarif", json.loads(stripped)
    except json.JSONDecodeError:
        return "unknown", None


# ---------------------------------------------------------------------------
# TruffleHog parser
# ---------------------------------------------------------------------------

def _extract_source_metadata(metadata):
    """Extract file, line, commit, repo, link from TruffleHog SourceMetadata."""
    info = {"file": "", "line": 0, "commit": "", "repository": "", "link": "", "email": ""}
    if not metadata or "Data" not in metadata:
        return info
    data = metadata["Data"]
    # Data contains a single key like "Git", "Github", "Filesystem", etc.
    for source_type, fields in data.items():
        if not isinstance(fields, dict):
            continue
        info["file"] = fields.get("file", "")
        info["line"] = fields.get("line", 0)
        info["commit"] = fields.get("commit", "")
        info["repository"] = fields.get("repository", "")
        info["link"] = fields.get("link", "")
        info["email"] = fields.get("email", "")
        break
    return info


def parse_trufflehog(results):
    """Convert TruffleHog JSON results to unified finding format."""
    findings = []
    for result in results:
        detector = result.get("DetectorName", "unknown")
        source_info = _extract_source_metadata(result.get("SourceMetadata"))
        verified = result.get("Verified", False)
        redacted = result.get("Redacted", "")
        extra_data = result.get("ExtraData") or {}

        level = "error" if verified else "warning"

        message_parts = [f"Secret detected by {detector}"]
        if verified:
            message_parts.append("(VERIFIED)")
        if redacted:
            message_parts.append(f": {redacted}")
        message = " ".join(message_parts)

        description_parts = []
        if result.get("DetectorDescription"):
            description_parts.append(result["DetectorDescription"])
        description_parts.append(f"Decoder: {result.get('DecoderName', 'PLAIN')}")
        if source_info["commit"]:
            description_parts.append(f"Commit: {source_info['commit'][:12]}")
        if source_info["email"]:
            description_parts.append(f"Author: {source_info['email']}")
        if source_info["repository"]:
            description_parts.append(f"Repo: {source_info['repository']}")
        for k, v in extra_data.items():
            description_parts.append(f"{k}: {v}")
        description = "\n".join(description_parts)

        # Build a fingerprint from detector + file + redacted value
        fp_source = f"{detector}:{source_info['file']}:{source_info['line']}:{redacted}"
        fingerprint = hashlib.sha256(fp_source.encode()).hexdigest()[:32]

        findings.append({
            "rule_id": f"trufflehog/{detector}",
            "rule_name": detector,
            "level": level,
            "message": message,
            "description": description,
            "short_desc": f"{detector} secret {'(verified)' if verified else '(unverified)'}",
            "help_uri": source_info["link"],
            "file": source_info["file"],
            "start_line": source_info["line"],
            "end_line": source_info["line"],
            "snippet": redacted or "[redacted]",
            "all_locations": [{
                "file": source_info["file"],
                "start_line": source_info["line"],
                "end_line": source_info["line"],
                "start_col": 0,
                "end_col": 0,
                "snippet": redacted or "[redacted]",
            }],
            "code_flows": [],
            "cwes": ["CWE-798"],  # Use of Hard-coded Credentials
            "owasps": [],
            "tags": [
                f"detector:{detector}",
                f"verified:{str(verified).lower()}",
                f"source:{result.get('SourceName', 'unknown')}",
            ],
            "source_tool": "TruffleHog",
            "fingerprint": fingerprint,
            "status": "new",
            "notes": "",
        })
    return findings


# ---------------------------------------------------------------------------
# gitleaks parser
# ---------------------------------------------------------------------------

def parse_gitleaks(results):
    """Convert gitleaks JSON results to unified finding format."""
    findings = []
    for result in results:
        rule_id = result.get("RuleID", "unknown")
        description = result.get("Description", "")
        file_path = result.get("File", "")
        start_line = result.get("StartLine", 0)
        end_line = result.get("EndLine", 0)
        start_col = result.get("StartColumn", 0)
        end_col = result.get("EndColumn", 0)
        match = result.get("Match", "")
        secret = result.get("Secret", "")
        commit = result.get("Commit", "")
        author = result.get("Author", "")
        email = result.get("Email", "")
        date = result.get("Date", "")
        commit_msg = result.get("Message", "")
        entropy = result.get("Entropy", 0)
        fingerprint = result.get("Fingerprint", "")
        tags = result.get("Tags") or []

        # Redact the secret in the match string
        redacted_secret = secret[:4] + "****" + secret[-4:] if len(secret) > 8 else "****"
        redacted_match = match.replace(secret, redacted_secret) if secret and match else match

        level = "error" if entropy > 4.0 else "warning"

        description_parts = [description]
        if commit:
            description_parts.append(f"Commit: {commit[:12]}")
        if author:
            description_parts.append(f"Author: {author}")
        if email:
            description_parts.append(f"Email: {email}")
        if date:
            description_parts.append(f"Date: {date}")
        if commit_msg:
            description_parts.append(f"Commit message: {commit_msg.strip()[:100]}")
        if entropy:
            description_parts.append(f"Entropy: {entropy:.2f}")
        full_description = "\n".join(description_parts)

        findings.append({
            "rule_id": f"gitleaks/{rule_id}",
            "rule_name": description or rule_id,
            "level": level,
            "message": f"Secret detected: {description} in {file_path}:{start_line}",
            "description": full_description,
            "short_desc": description,
            "help_uri": result.get("Link", ""),
            "file": file_path,
            "start_line": start_line,
            "end_line": end_line,
            "snippet": redacted_match,
            "all_locations": [{
                "file": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "start_col": start_col,
                "end_col": end_col,
                "snippet": redacted_match,
            }],
            "code_flows": [],
            "cwes": ["CWE-798"],
            "owasps": [],
            "tags": tags + [f"rule:{rule_id}"],
            "source_tool": "gitleaks",
            "fingerprint": fingerprint or hashlib.sha256(
                f"{rule_id}:{file_path}:{start_line}:{commit}".encode()
            ).hexdigest()[:32],
            "status": "new",
            "notes": "",
        })
    return findings


def parse_sarif(sarif_data):
    findings = []
    for run in sarif_data.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "Unknown")
        rules = {}
        for r in run.get("tool", {}).get("driver", {}).get("rules", []):
            rules[r["id"]] = r
        for ext in run.get("tool", {}).get("extensions", []):
            for r in ext.get("rules", []):
                rules[r["id"]] = r

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule = rules.get(rule_id, {})

            level = result.get("level")
            if not level or level == "none":
                level = rule.get("defaultConfiguration", {}).get("level", "warning")

            tags = rule.get("properties", {}).get("tags", [])
            cwes = [t for t in tags if t.startswith("CWE-")]
            owasps = [t for t in tags if "OWASP" in t]

            locations = []
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {}).get("uri", "")
                region = phys.get("region", {})
                locations.append({
                    "file": artifact,
                    "start_line": region.get("startLine", 0),
                    "end_line": region.get("endLine", 0),
                    "start_col": region.get("startColumn", 0),
                    "end_col": region.get("endColumn", 0),
                    "snippet": region.get("snippet", {}).get("text", "").strip(),
                })

            code_flows = []
            for cf in result.get("codeFlows", []):
                for tf in cf.get("threadFlows", []):
                    flow_steps = []
                    for tfl in tf.get("locations", []):
                        loc = tfl.get("location", {})
                        phys = loc.get("physicalLocation", {})
                        flow_steps.append({
                            "file": phys.get("artifactLocation", {}).get("uri", ""),
                            "line": phys.get("region", {}).get("startLine", 0),
                            "snippet": phys.get("region", {}).get("snippet", {}).get("text", "").strip(),
                            "message": loc.get("message", {}).get("text", ""),
                        })
                    if flow_steps:
                        code_flows.append(flow_steps)

            findings.append({
                "rule_id": rule_id,
                "rule_name": rule.get("name", rule_id),
                "level": level,
                "message": result.get("message", {}).get("text", ""),
                "description": rule.get("fullDescription", {}).get("text", ""),
                "short_desc": rule.get("shortDescription", {}).get("text", ""),
                "help_uri": rule.get("helpUri", ""),
                "file": locations[0]["file"] if locations else "",
                "start_line": locations[0]["start_line"] if locations else 0,
                "end_line": locations[0]["end_line"] if locations else 0,
                "snippet": locations[0]["snippet"] if locations else "",
                "all_locations": locations,
                "code_flows": code_flows,
                "cwes": cwes,
                "owasps": owasps,
                "tags": tags,
                "source_tool": result.get("properties", {}).get("source_tool", tool_name),
                "fingerprint": result.get("fingerprints", {}).get("matchBasedId/v1", ""),
                "status": "new",
                "notes": "",
            })
    return findings


# ---------------------------------------------------------------------------
# JSON helper
# ---------------------------------------------------------------------------

def serialize(doc):
    doc["_id"] = str(doc["_id"])
    doc["project_id"] = str(doc["project_id"])
    if "created_at" in doc:
        doc["created_at"] = doc["created_at"].isoformat()
    if "updated_at" in doc:
        doc["updated_at"] = doc["updated_at"].isoformat()
    return doc


def serialize_project(doc):
    doc["_id"] = str(doc["_id"])
    if "uploaded_at" in doc:
        doc["uploaded_at"] = doc["uploaded_at"].isoformat()
    doc.pop("original_sarif", None)
    doc.pop("original_sarifs", None)
    return doc


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/projects", methods=["GET"])
def list_projects():
    docs = list(projects_col.find({}, {"original_sarif": 0, "original_sarifs": 0}).sort("uploaded_at", -1))
    return jsonify([serialize_project(d) for d in docs])


@app.route("/api/projects", methods=["POST"])
def create_project():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    now = datetime.now(timezone.utc)
    project = {
        "name": name,
        "uploaded_at": now,
        "finding_count": 0,
        "source_format": None,
        "original_sarifs": [],
    }
    pid = projects_col.insert_one(project).inserted_id
    return jsonify({"_id": str(pid), "name": name})


def insert_findings_for_project(project_id, findings, fmt, filename="scan"):
    """Insert findings with deduplication — shared between upload and scan.

    Returns (inserted_count, duplicates_removed).
    """
    now = datetime.now(timezone.utc)

    for fnd in findings:
        fnd["dedup_hash"] = compute_dedup_hash(fnd)

    duplicates_removed = 0
    if findings:
        new_hashes = [fnd["dedup_hash"] for fnd in findings]
        existing = set(
            doc["dedup_hash"]
            for doc in findings_col.find(
                {"project_id": project_id, "dedup_hash": {"$in": new_hashes}},
                {"dedup_hash": 1},
            )
        )
        if existing:
            original_count = len(findings)
            findings = [fnd for fnd in findings if fnd["dedup_hash"] not in existing]
            duplicates_removed = original_count - len(findings)

    if findings:
        for fnd in findings:
            fnd["project_id"] = project_id
            fnd["created_at"] = now
            fnd["updated_at"] = now
        findings_col.insert_many(findings)

    # Update project finding count
    projects_col.update_one({"_id": project_id}, {"$inc": {"finding_count": len(findings)}})

    return len(findings), duplicates_removed


@app.route("/api/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "no file"}), 400

    project_id_str = request.form.get("project_id")
    if not project_id_str:
        return jsonify({"error": "project_id is required"}), 400
    try:
        project_id = ObjectId(project_id_str)
    except Exception:
        return jsonify({"error": "invalid project_id"}), 400

    project = projects_col.find_one({"_id": project_id})
    if not project:
        return jsonify({"error": "project not found"}), 404

    try:
        raw_text = f.read().decode("utf-8", errors="replace")
    except Exception:
        return jsonify({"error": "cannot read file"}), 400

    fmt, parsed = detect_format(raw_text)

    if fmt == "sarif":
        findings = parse_sarif(parsed)
        original_data = parsed
    elif fmt == "trufflehog":
        findings = parse_trufflehog(parsed)
        original_data = {"_trufflehog_results": parsed, "_format": "trufflehog"}
    elif fmt == "gitleaks":
        findings = parse_gitleaks(parsed)
        original_data = {"_gitleaks_results": parsed, "_format": "gitleaks"}
    else:
        return jsonify({"error": "unsupported format (expected SARIF, TruffleHog or gitleaks JSON)"}), 400

    inserted, duplicates_removed = insert_findings_for_project(project_id, findings, fmt, f.filename or "unknown")

    # Append original data and set format if first upload
    update_ops = {
        "$push": {"original_sarifs": {"filename": f.filename or "unknown", "format": fmt, "data": original_data}},
    }
    if not project.get("source_format"):
        update_ops.setdefault("$set", {})["source_format"] = fmt
    projects_col.update_one({"_id": project_id}, update_ops)

    return jsonify({
        "project_id": str(project_id),
        "count": inserted,
        "duplicates_removed": duplicates_removed,
        "format": fmt,
    })


@app.route("/api/findings", methods=["GET"])
def list_findings():
    project_id = request.args.get("project_id")
    if not project_id:
        return jsonify({"error": "project_id required"}), 400
    try:
        pid = ObjectId(project_id)
    except Exception:
        return jsonify({"error": "invalid project_id"}), 400

    query = {"project_id": pid, "deleted_at": {"$exists": False}}

    status = request.args.get("status")
    if status:
        query["status"] = {"$in": status.split(",")}

    level = request.args.get("level")
    if level:
        query["level"] = {"$in": level.split(",")}

    tool = request.args.get("tool")
    if tool:
        query["source_tool"] = {"$in": tool.split(",")}

    search = request.args.get("q")
    if search:
        query["$or"] = [
            {"rule_id": {"$regex": search, "$options": "i"}},
            {"file": {"$regex": search, "$options": "i"}},
            {"message": {"$regex": search, "$options": "i"}},
            {"snippet": {"$regex": search, "$options": "i"}},
        ]

    docs = list(findings_col.find(query).sort([("level", 1), ("rule_id", 1)]))
    return jsonify([serialize(d) for d in docs])


@app.route("/api/findings/counts", methods=["GET"])
def finding_counts():
    """Return unfiltered level/status counts for a project."""
    project_id = request.args.get("project_id")
    if not project_id:
        return jsonify({"error": "project_id required"}), 400
    try:
        pid = ObjectId(project_id)
    except Exception:
        return jsonify({"error": "invalid project_id"}), 400

    pipeline = [
        {"$match": {"project_id": pid, "deleted_at": {"$exists": False}}},
        {"$group": {
            "_id": {"level": "$level", "status": "$status", "tool": "$source_tool"},
            "count": {"$sum": 1},
        }},
    ]
    levels = {}
    statuses = {}
    tools = {}
    total = 0
    for doc in findings_col.aggregate(pipeline):
        lvl = doc["_id"]["level"]
        st = doc["_id"]["status"]
        tl = doc["_id"].get("tool") or "Unknown"
        c = doc["count"]
        levels[lvl] = levels.get(lvl, 0) + c
        statuses[st] = statuses.get(st, 0) + c
        tools[tl] = tools.get(tl, 0) + c
        total += c

    return jsonify({"levels": levels, "statuses": statuses, "tools": tools, "total": total})


@app.route("/api/findings/<finding_id>", methods=["PATCH"])
def update_finding(finding_id):
    try:
        fid = ObjectId(finding_id)
    except Exception:
        return jsonify({"error": "invalid id"}), 400

    data = request.get_json(force=True)
    update = {"updated_at": datetime.now(timezone.utc)}

    if "status" in data and data["status"] in STATUSES:
        update["status"] = data["status"]
    if "notes" in data:
        update["notes"] = str(data["notes"])[:2000]

    findings_col.update_one({"_id": fid}, {"$set": update})
    return jsonify({"ok": True})


@app.route("/api/findings/bulk", methods=["PATCH"])
def bulk_update():
    data = request.get_json(force=True)
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"error": "no ids"}), 400

    update = {"updated_at": datetime.now(timezone.utc)}
    if "status" in data and data["status"] in STATUSES:
        update["status"] = data["status"]

    oids = []
    for i in ids:
        try:
            oids.append(ObjectId(i))
        except Exception:
            pass

    if oids:
        findings_col.update_many({"_id": {"$in": oids}}, {"$set": update})
    return jsonify({"ok": True, "updated": len(oids)})


@app.route("/api/findings/bulk-delete", methods=["POST"])
def bulk_delete_findings():
    data = request.get_json(force=True)
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"error": "no ids"}), 400

    oids = []
    for i in ids:
        try:
            oids.append(ObjectId(i))
        except Exception:
            pass

    if not oids:
        return jsonify({"error": "no valid ids"}), 400

    now = datetime.now(timezone.utc)

    # Soft-delete: set deleted_at timestamp instead of removing
    result = findings_col.update_many(
        {"_id": {"$in": oids}, "deleted_at": {"$exists": False}},
        {"$set": {"deleted_at": now}},
    )

    # Decrement finding_count on affected projects
    affected = list(findings_col.find({"_id": {"$in": oids}, "deleted_at": now}, {"project_id": 1}))
    project_counts = {}
    for doc in affected:
        pid = doc["project_id"]
        project_counts[pid] = project_counts.get(pid, 0) + 1
    for pid, count in project_counts.items():
        projects_col.update_one({"_id": pid}, {"$inc": {"finding_count": -count}})

    return jsonify({"ok": True, "deleted": result.modified_count, "ids": [str(o) for o in oids]})


@app.route("/api/findings/restore", methods=["POST"])
def restore_findings():
    data = request.get_json(force=True)
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"error": "no ids"}), 400

    oids = []
    for i in ids:
        try:
            oids.append(ObjectId(i))
        except Exception:
            pass

    if not oids:
        return jsonify({"error": "no valid ids"}), 400

    # Count per project before restoring
    affected = list(findings_col.find({"_id": {"$in": oids}, "deleted_at": {"$exists": True}}, {"project_id": 1}))
    project_counts = {}
    for doc in affected:
        pid = doc["project_id"]
        project_counts[pid] = project_counts.get(pid, 0) + 1

    result = findings_col.update_many(
        {"_id": {"$in": oids}, "deleted_at": {"$exists": True}},
        {"$unset": {"deleted_at": ""}},
    )

    # Re-increment finding_count on affected projects
    for pid, count in project_counts.items():
        projects_col.update_one({"_id": pid}, {"$inc": {"finding_count": count}})

    return jsonify({"ok": True, "restored": result.modified_count})


@app.route("/api/projects/<project_id>", methods=["DELETE"])
def delete_project(project_id):
    try:
        pid = ObjectId(project_id)
    except Exception:
        return jsonify({"error": "invalid id"}), 400
    findings_col.delete_many({"project_id": pid})
    projects_col.delete_one({"_id": pid})
    return jsonify({"ok": True})


@app.route("/api/projects/bulk-delete", methods=["POST"])
def bulk_delete_projects():
    data = request.get_json(force=True)
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"error": "no ids provided"}), 400
    try:
        oids = [ObjectId(i) for i in ids]
    except Exception:
        return jsonify({"error": "invalid id in list"}), 400
    findings_col.delete_many({"project_id": {"$in": oids}})
    result = projects_col.delete_many({"_id": {"$in": oids}})
    return jsonify({"ok": True, "deleted": result.deleted_count})


@app.route("/api/export/<project_id>", methods=["GET"])
def export_sarif(project_id):
    try:
        pid = ObjectId(project_id)
    except Exception:
        return jsonify({"error": "invalid id"}), 400

    project = projects_col.find_one({"_id": pid})
    if not project:
        return jsonify({"error": "not found"}), 404

    findings_map = {f["fingerprint"]: f for f in findings_col.find({"project_id": pid}) if f.get("fingerprint")}

    def inject_review(sarif_data):
        for run in sarif_data.get("runs", []):
            for result in run.get("results", []):
                fp = result.get("fingerprints", {}).get("matchBasedId/v1", "")
                if fp in findings_map:
                    props = result.setdefault("properties", {})
                    props["review_status"] = findings_map[fp]["status"]
                    props["review_notes"] = findings_map[fp].get("notes", "")

    # Support both old single original_sarif and new original_sarifs list
    original_sarifs = project.get("original_sarifs", [])
    old_sarif = project.get("original_sarif")

    if original_sarifs:
        # Merge all SARIF runs into one export document
        merged = {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json", "version": "2.1.0", "runs": []}
        for entry in original_sarifs:
            data = entry.get("data", {})
            if isinstance(data, dict) and "runs" in data:
                inject_review(data)
                merged["runs"].extend(data["runs"])
            else:
                # Non-SARIF formats stored as-is; include as a single run note
                merged["runs"].append({"tool": {"driver": {"name": entry.get("format", "unknown")}}, "results": [], "_importedData": data})
        export_data = merged
    elif old_sarif:
        inject_review(old_sarif)
        export_data = old_sarif
    else:
        export_data = {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json", "version": "2.1.0", "runs": []}

    filename = project["name"]
    if not filename.endswith(".sarif") and not filename.endswith(".json"):
        filename += ".sarif"

    return Response(
        json.dumps(export_data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ---------------------------------------------------------------------------
# Scan execution
# ---------------------------------------------------------------------------

def _validate_repo_url(url):
    """Validate that a repo URL is a safe HTTP(S) Git URL."""
    if not url or not isinstance(url, str):
        return False
    url = url.strip()
    if not re.match(r'^https?://', url, re.IGNORECASE):
        return False
    # Block file://, ftp://, ssh://, etc.
    if re.match(r'^(file|ftp|ssh|git)://', url, re.IGNORECASE):
        return False
    return True


def _update_scan(scan_id, **fields):
    """Update scan document fields."""
    scans_col.update_one({"_id": scan_id}, {"$set": fields})


def _get_settings_dict():
    """Return a dict of all settings {key: value}."""
    return {doc["key"]: doc.get("value", "") for doc in settings_col.find({"key": {"$in": SETTINGS_KEYS}})}


def _get_scanner_env(settings=None):
    """Build environment dict with tokens from settings collection."""
    if settings is None:
        settings = _get_settings_dict()
    env = os.environ.copy()
    if settings.get("snyk_token"):
        env["SNYK_TOKEN"] = settings["snyk_token"]
        subprocess.run(
            ["snyk", "auth", settings["snyk_token"], "--auth-type=token"],
            capture_output=True, text=True, timeout=30, env=env
        )
    if settings.get("github_token"):
        env["GITHUB_TOKEN"] = settings["github_token"]
    # Note: SEMGREP_APP_TOKEN is NOT set here — it's injected only for semgrep ci
    return env


def _run_scanner_command(tool, repo_dir, output_file, env=None):
    """Run the appropriate scanner command and return (success, stdout, stderr)."""
    timeout = 600  # 10 minutes
    run_kw = dict(capture_output=True, text=True, timeout=timeout)
    if env is not None:
        run_kw["env"] = env

    try:
        if tool == "semgrep":
            semgrep_token = _get_settings_dict().get("semgrep_token")
            use_ci = bool(semgrep_token)
            if use_ci:
                # Try semgrep ci with Cloud Platform rules
                ci_env = dict(env or os.environ.copy())
                ci_env["SEMGREP_APP_TOKEN"] = semgrep_token
                ci_kw = dict(run_kw)
                ci_kw["env"] = ci_env
                ci_kw["cwd"] = repo_dir
                cmd = ["semgrep", "ci", "--sarif", f"--sarif-output={output_file}"]
                result = subprocess.run(cmd, **ci_kw)
                # Detect auth failure and fallback to semgrep scan
                combined = (result.stdout or "") + (result.stderr or "")
                if "API token not valid" in combined or "HTTP 401" in combined:
                    use_ci = False
            if not use_ci:
                # Ensure no stale api_token in semgrep settings causes 401
                subprocess.run(["semgrep", "logout"], capture_output=True, text=True, timeout=10)
                cmd = ["semgrep", "scan", "--config=p/default",
                       "--metrics=off", "--sarif", f"--sarif-output={output_file}", repo_dir]
                result = subprocess.run(cmd, **run_kw)
            return result.returncode in (0, 1), result.stdout, result.stderr

        elif tool == "snyk":
            # snyk code test returns 1 when vulns are found
            cmd = ["snyk", "code", "test", f"--sarif-file-output={output_file}", repo_dir]
            result = subprocess.run(cmd, **run_kw)
            return result.returncode in (0, 1), result.stdout, result.stderr

        elif tool == "codeql":
            db_dir = os.path.join(os.path.dirname(output_file), "codeql-db")
            lang = "javascript"
            for ext, l in [(".py", "python"), (".java", "java"), (".go", "go"),
                           (".rb", "ruby"), (".cs", "csharp"), (".cpp", "cpp"),
                           (".c", "cpp"), (".js", "javascript"), (".ts", "javascript")]:
                for root, dirs, files in os.walk(repo_dir):
                    if any(f.endswith(ext) for f in files):
                        lang = l
                        break
                else:
                    continue
                break

            result = subprocess.run(
                ["codeql", "database", "create", db_dir, f"--source-root={repo_dir}", f"--language={lang}", "--overwrite"],
                **run_kw
            )
            if result.returncode != 0:
                return False, result.stdout, result.stderr

            result = subprocess.run(
                ["codeql", "database", "analyze", db_dir, f"--format=sarif-latest", f"--output={output_file}"],
                **run_kw
            )
            return result.returncode == 0, result.stdout, result.stderr

        elif tool == "trufflehog":
            cmd = ["trufflehog", "filesystem", repo_dir, "--json"]
            result = subprocess.run(cmd, **run_kw)
            with open(output_file, "w") as f:
                f.write(result.stdout)
            return True, result.stdout, result.stderr

        elif tool == "gitleaks":
            cmd = ["gitleaks", "detect", f"--source={repo_dir}", "--report-format=json", f"--report-path={output_file}"]
            result = subprocess.run(cmd, **run_kw)
            return result.returncode in (0, 1), result.stdout, result.stderr

        else:
            return False, "", f"Unknown scanner: {tool}"

    except FileNotFoundError:
        return False, "", f"Scanner binary '{tool}' not found in PATH. Is it installed?"


def _repo_name_from_url(url):
    """Extract a safe directory name from a git URL."""
    # https://github.com/user/repo.git -> user_repo
    path = re.sub(r'^https?://', '', url).rstrip('/')
    path = re.sub(r'\.git$', '', path)
    # Keep only the last 2 segments (user/repo)
    parts = path.split('/')
    name = '_'.join(parts[-2:]) if len(parts) >= 2 else parts[-1]
    # Sanitize: only keep alphanumeric, dash, underscore
    name = re.sub(r'[^a-zA-Z0-9_\-]', '_', name)
    return name or "repo"


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
        # Build env with tokens from settings
        settings = _get_settings_dict()
        scanner_env = _get_scanner_env(settings)

        # Clone
        _update_scan(scan_id, status="cloning")
        repo_name = _repo_name_from_url(repo_url)
        tmpdir = os.path.join(SCAN_REPO_BASE, f"{repo_name}_{scan_id}")
        os.makedirs(tmpdir, exist_ok=True)
        repo_dir = os.path.join(tmpdir, repo_name)

        clone_cmd = ["git", "clone", "--depth", "1"]
        if branch:
            clone_cmd.extend(["--branch", branch])
        clone_cmd.extend([repo_url, repo_dir])

        clone_result = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=120, env=scanner_env)
        if clone_result.returncode != 0:
            _update_scan(scan_id, status="failed",
                         error=f"Git clone failed: {clone_result.stderr[:2000]}",
                         completed_at=datetime.now(timezone.utc))
            return

        # Run scanner
        _update_scan(scan_id, status="running")
        output_file = os.path.join(tmpdir, "output.json")

        success, stdout, stderr = _run_scanner_command(tool, repo_dir, output_file, env=scanner_env)

        log_text = (stdout + "\n" + stderr)[:10000]
        _update_scan(scan_id, log=log_text)

        if not success:
            # Filter out non-fatal warnings from stderr
            error_lines = [l for l in stderr.strip().splitlines()
                           if not l.startswith("METRICS:") and "semgrep.dev/docs/metrics" not in l
                           and l.strip()]
            error_detail = "\n".join(error_lines) or stdout.strip() or "No output (scanner may have crashed)"
            _update_scan(scan_id, status="failed",
                         error=f"Scanner failed: {error_detail[:2000]}",
                         completed_at=datetime.now(timezone.utc))
            return

        # Parse output
        _update_scan(scan_id, status="parsing")

        output_format = scanner_info["output_format"]
        findings = []

        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, "r") as f:
                raw_text = f.read()

            if output_format == "sarif":
                try:
                    sarif_data = json.loads(raw_text)
                    findings = parse_sarif(sarif_data)
                except json.JSONDecodeError as e:
                    _update_scan(scan_id, status="failed",
                                 error=f"Failed to parse SARIF output: {str(e)}",
                                 completed_at=datetime.now(timezone.utc))
                    return
            elif output_format == "trufflehog":
                fmt, parsed = detect_format(raw_text)
                if fmt == "trufflehog":
                    findings = parse_trufflehog(parsed)
            elif output_format == "gitleaks":
                fmt, parsed = detect_format(raw_text)
                if fmt == "gitleaks":
                    findings = parse_gitleaks(parsed)

        # Insert findings
        inserted, duplicates = insert_findings_for_project(project_id, findings, output_format, f"scan-{tool}")

        # Re-read scan to get the started_at from DB (always use aware datetime)
        completed = datetime.now(timezone.utc)
        started = scan.get("started_at")
        if started and started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        duration = (completed - started).total_seconds() if started else 0

        _update_scan(scan_id,
                     status="completed",
                     completed_at=completed,
                     duration_seconds=round(duration, 1),
                     findings_count=inserted,
                     duplicates_count=duplicates)

    except subprocess.TimeoutExpired:
        _update_scan(scan_id, status="failed",
                     error="Scanner timed out (10 min limit)",
                     completed_at=datetime.now(timezone.utc))
    except Exception as e:
        _update_scan(scan_id, status="failed",
                     error=str(e)[:2000],
                     completed_at=datetime.now(timezone.utc))
    finally:
        if tmpdir and os.path.exists(tmpdir):
            shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Scan endpoints
# ---------------------------------------------------------------------------

@app.route("/api/scanners", methods=["GET"])
def list_scanners():
    """List available scanners and their descriptions."""
    result = []
    for name, info in SCANNERS.items():
        result.append({
            "name": name,
            "description": info["description"],
            "output_format": info["output_format"],
        })
    return jsonify(result)


@app.route("/api/scans", methods=["POST"])
def create_scan():
    data = request.get_json(force=True)

    project_id_str = data.get("project_id")
    tool = data.get("tool")
    repo_url = (data.get("repo_url") or "").strip()
    branch = (data.get("branch") or "").strip() or None

    if not project_id_str:
        return jsonify({"error": "project_id is required"}), 400
    try:
        project_id = ObjectId(project_id_str)
    except Exception:
        return jsonify({"error": "invalid project_id"}), 400

    if not projects_col.find_one({"_id": project_id}):
        return jsonify({"error": "project not found"}), 404

    if not _validate_repo_url(repo_url):
        return jsonify({"error": "invalid repo URL — only http:// and https:// URLs are allowed"}), 400

    # "all" launches one scan per tool
    tools_to_run = list(SCANNERS.keys()) if tool == "all" else [tool]

    for t in tools_to_run:
        if t not in SCANNERS:
            return jsonify({"error": f"unknown scanner: {t}. Available: {', '.join(SCANNERS.keys())}"}), 400

    # Check token requirements
    settings = _get_settings_dict()
    TOKEN_LABELS = {"snyk_token": "Snyk", "semgrep_token": "Semgrep"}
    missing = []
    for t in tools_to_run:
        req = SCANNERS[t].get("requires_token")
        if req and not settings.get(req):
            missing.append(TOKEN_LABELS.get(req, req))
    if missing:
        names = ", ".join(missing)
        return jsonify({"error": f"Missing token(s) for {names}. Configure them in Settings (gear icon)."}), 400

    os.makedirs(SCAN_REPO_BASE, exist_ok=True)

    scan_ids = []
    now = datetime.now(timezone.utc)
    for t in tools_to_run:
        scan_doc = {
            "project_id": project_id,
            "tool": t,
            "status": "pending",
            "repo_url": repo_url,
            "branch": branch,
            "config": data.get("config", {}),
            "started_at": now,
            "completed_at": None,
            "duration_seconds": None,
            "log": "",
            "error": "",
            "findings_count": 0,
            "duplicates_count": 0,
            "created_at": now,
        }
        sid = scans_col.insert_one(scan_doc).inserted_id
        scan_ids.append(str(sid))
        scan_executor.submit(run_scan, sid)

    return jsonify({"ids": scan_ids, "status": "pending", "count": len(scan_ids)})


@app.route("/api/scans", methods=["GET"])
def list_scans():
    project_id = request.args.get("project_id")
    if not project_id:
        return jsonify({"error": "project_id required"}), 400
    try:
        pid = ObjectId(project_id)
    except Exception:
        return jsonify({"error": "invalid project_id"}), 400

    docs = list(scans_col.find({"project_id": pid}).sort("created_at", -1))
    result = []
    for d in docs:
        d["_id"] = str(d["_id"])
        d["project_id"] = str(d["project_id"])
        for field in ("created_at", "started_at", "completed_at"):
            if d.get(field):
                d[field] = d[field].isoformat()
        result.append(d)
    return jsonify(result)


@app.route("/api/scans/<scan_id>", methods=["GET"])
def get_scan(scan_id):
    try:
        sid = ObjectId(scan_id)
    except Exception:
        return jsonify({"error": "invalid id"}), 400

    d = scans_col.find_one({"_id": sid})
    if not d:
        return jsonify({"error": "not found"}), 404

    d["_id"] = str(d["_id"])
    d["project_id"] = str(d["project_id"])
    for field in ("created_at", "started_at", "completed_at"):
        if d.get(field):
            d[field] = d[field].isoformat()
    return jsonify(d)


@app.route("/api/scans/<scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    try:
        sid = ObjectId(scan_id)
    except Exception:
        return jsonify({"error": "invalid id"}), 400
    scans_col.delete_one({"_id": sid})
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# SVG renderer (ported from sarif_toolkit.py)
# ---------------------------------------------------------------------------

E = html.escape


def _severity_color(level, dark=True):
    if dark:
        return {"error": "#ff5555", "warning": "#ffb86c", "note": "#8be9fd", "info": "#8be9fd"}.get(level, "#6272a4")
    return {"error": "#c0392b", "warning": "#e67e22", "note": "#2980b9", "info": "#2980b9"}.get(level, "#7f8c8d")


def _theme_palette(dark=True):
    if dark:
        return {
            "canvas_bg": "#282a36",
            "box_bg": "#44475a",
            "box_text": "#f8f8f2",
            "box_sub": "#6272a4",
            "detail_bg": "#343746",
            "detail_border": "#6272a4",
            "detail_text": "#f8f8f2",
            "detail_danger": "#ff5555",
            "file_ref": "#6272a4",
            "desc_bg": "#343746",
            "desc_border": "#6272a4",
            "desc_text": "#cdd6f4",
            "rule_color": "#bd93f9",
            "source_color": "#ff5555",
            "sink_color": "#ff5555",
            "step_color": "#8be9fd",
        }
    return {
        "canvas_bg": "#fafafa",
        "box_bg": "white",
        "box_text": "#2c3e50",
        "box_sub": "#7f8c8d",
        "detail_bg": "#f8f9fa",
        "detail_border": "#dee2e6",
        "detail_text": "#495057",
        "detail_danger": "#c0392b",
        "file_ref": "#6c757d",
        "desc_bg": "#eef2f7",
        "desc_border": "#bdc3c7",
        "desc_text": "#34495e",
        "rule_color": "#8e44ad",
        "source_color": "#e74c3c",
        "sink_color": "#c0392b",
        "step_color": "#3498db",
    }


def _cwe_short(cwe_str):
    m = re.match(r"(CWE-\d+)", cwe_str)
    return m.group(1) if m else cwe_str[:20]


def _rule_short_name(rule_id):
    parts = rule_id.split(".")
    return parts[-1] if parts else rule_id


def _wrap_text(text, width=60):
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    out = []
    for raw_line in text.split("\n"):
        line = raw_line
        while len(line) > width:
            idx = line.rfind(" ", 0, width)
            if idx <= 0:
                idx = width
            out.append(line[:idx])
            line = line[idx:].lstrip()
        out.append(line)
    return out[:20]


def render_finding_svg(finding, finding_index=0, dark=True):
    elements = []
    chain_id = f"f{finding_index}"
    pal = _theme_palette(dark)

    CANVAS_W = 1240
    BOX_W = 560
    DETAIL_W = 560
    BOX_H = 80
    GAP_Y = 34
    MARGIN_X = 34
    LEFT_X = MARGIN_X
    RIGHT_X = MARGIN_X + BOX_W + 24
    ARROW_X = LEFT_X + BOX_W // 2

    sev_color = _severity_color(finding["level"], dark)
    cwe_label = ", ".join(_cwe_short(c) for c in finding.get("cwes", [])) if finding.get("cwes") else "N/A"
    locations = finding.get("all_locations", [])
    n_locations = len(locations)

    source_tool = finding.get("source_tool", "")
    tool_badge = f"  [{source_tool}]" if source_tool else ""

    elements.append(f'''
        <defs>
            <marker id="ah-{chain_id}" viewBox="0 0 10 10" refX="9" refY="5"
                    markerWidth="7" markerHeight="5" orient="auto">
                <path d="M0 0 L10 5 L0 10z" fill="{sev_color}"/>
            </marker>
        </defs>''')

    title_text = f"[{finding['level'].upper()}] {finding['rule_id']}"
    count_text = f"x{n_locations}" if n_locations > 1 else ""

    elements.append(f'''
        <rect x="10" y="10" width="{CANVAS_W - 20}" height="38" rx="5"
              fill="{sev_color}" opacity="0.9"/>
        <text x="22" y="34" font-size="14" font-weight="bold" fill="white"
              font-family="monospace">{E(title_text)}{E(tool_badge)}</text>
        <text x="{CANVAS_W - 30}" y="34" font-size="12" fill="white" text-anchor="end"
              font-family="monospace">{E(cwe_label)}  {E(count_text)}</text>''')

    cursor_y = 58

    def _draw_step(label, label_color, title, subtitle, detail_text, file_ref, y):
        parts = []
        detail_lines = _wrap_text(detail_text, 62)
        detail_h = max(BOX_H, len(detail_lines) * 16 + 30)
        row_h = max(BOX_H, detail_h)

        parts.append(f'''
        <g transform="translate({LEFT_X}, {y})">
            <rect width="{BOX_W}" height="24" rx="3" fill="{label_color}" opacity="0.85"/>
            <text x="{BOX_W // 2}" y="16" text-anchor="middle" font-size="11" fill="white"
                  font-weight="bold" font-family="monospace">{E(label)}</text>
            <rect y="24" width="{BOX_W}" height="{row_h - 24}" fill="{pal['box_bg']}"
                  stroke="{label_color}" stroke-width="2"/>
            <text x="{BOX_W // 2}" y="46" text-anchor="middle" font-size="13"
                  font-weight="bold" fill="{pal['box_text']}" font-family="monospace">{E(title)}</text>
            <text x="{BOX_W // 2}" y="64" text-anchor="middle" font-size="11"
                  fill="{pal['box_sub']}" font-family="monospace">{E(subtitle)}</text>
        </g>''')

        parts.append(f'''
        <g transform="translate({RIGHT_X}, {y})">
            <rect width="{DETAIL_W}" height="{row_h}" rx="4" fill="{pal['detail_bg']}"
                  stroke="{pal['detail_border']}" stroke-width="1" stroke-dasharray="4,2"/>''')
        for li, line in enumerate(detail_lines):
            clr = pal["detail_danger"] if any(kw in line.lower() for kw in [
                "danger", "vulner", "inject", "unsanit", "malicious",
            ]) else pal["detail_text"]
            parts.append(f'''
            <text x="12" y="{18 + li * 16}" font-size="11" fill="{clr}"
                  font-family="monospace">{E(line)}</text>''')

        file_display = file_ref
        if len(file_display) > 64:
            file_display = "..." + file_display[-61:]
        parts.append(f'''
            <text x="12" y="{row_h - 6}" font-size="10" fill="{pal['file_ref']}"
                  font-style="italic" font-family="monospace">{E(file_display)}</text>
        </g>''')

        return "\n".join(parts), row_h

    # RULE step
    rule_svg, rule_h = _draw_step(
        label="RULE", label_color=pal["rule_color"],
        title=_rule_short_name(finding["rule_id"]),
        subtitle=cwe_label,
        detail_text=(finding.get("message") or "")[:250],
        file_ref=finding.get("help_uri") or finding["rule_id"],
        y=cursor_y,
    )
    elements.append(rule_svg)
    cursor_y = cursor_y + rule_h + GAP_Y

    code_flows = finding.get("code_flows", [])

    if code_flows:
        flow = code_flows[0]
        for fi, fstep in enumerate(flow):
            is_first = (fi == 0)
            is_last = (fi == len(flow) - 1)
            label = "SOURCE" if is_first else ("SINK" if is_last else f"STEP {fi}")
            color = pal["source_color"] if is_first else (pal["sink_color"] if is_last else pal["step_color"])

            elements.append(f'''
        <line x1="{ARROW_X}" y1="{cursor_y - GAP_Y + 3}" x2="{ARROW_X}" y2="{cursor_y - 3}"
              stroke="{sev_color}" stroke-width="2" marker-end="url(#ah-{chain_id})"/>''')

            step_svg, step_h = _draw_step(
                label=label, label_color=color,
                title=os.path.basename(fstep["file"]),
                subtitle=f"L{fstep['line']}",
                detail_text=fstep["message"] or fstep["snippet"],
                file_ref=f"{fstep['file']}:{fstep['line']}",
                y=cursor_y,
            )
            elements.append(step_svg)
            cursor_y += step_h + GAP_Y

    elif n_locations <= 3:
        for li, loc in enumerate(locations):
            elements.append(f'''
        <line x1="{ARROW_X}" y1="{cursor_y - GAP_Y + 3}" x2="{ARROW_X}" y2="{cursor_y - 3}"
              stroke="{sev_color}" stroke-width="2" marker-end="url(#ah-{chain_id})"/>''')

            step_svg, step_h = _draw_step(
                label=f"FINDING {li + 1}/{n_locations}" if n_locations > 1 else "FINDING",
                label_color=sev_color,
                title=os.path.basename(loc["file"]),
                subtitle=f"L{loc['start_line']}-L{loc['end_line']}  C{loc.get('start_col', 0)}-C{loc.get('end_col', 0)}",
                detail_text=loc["snippet"],
                file_ref=f"{loc['file']}:{loc['start_line']}",
                y=cursor_y,
            )
            elements.append(step_svg)
            cursor_y += step_h + GAP_Y
    else:
        elements.append(f'''
        <line x1="{ARROW_X}" y1="{cursor_y - GAP_Y + 3}" x2="{ARROW_X}" y2="{cursor_y - 3}"
              stroke="{sev_color}" stroke-width="2" marker-end="url(#ah-{chain_id})"/>''')

        file_list_lines = [f"{loc['file']}:{loc['start_line']}" for loc in locations]
        snippet = locations[0]["snippet"] if locations else ""

        step_svg, step_h = _draw_step(
            label=f"FINDINGS ({n_locations} occurrences)", label_color=sev_color,
            title="Multiple files",
            subtitle=f"{n_locations} locations with same pattern",
            detail_text=snippet + "\n\n" + "\n".join(file_list_lines),
            file_ref=f"{n_locations} files affected",
            y=cursor_y,
        )
        elements.append(step_svg)
        cursor_y += step_h + GAP_Y

    # Description box
    desc = finding.get("description") or finding.get("message") or ""
    if finding.get("help_uri"):
        desc += f"\n\nRef: {finding['help_uri']}"
    if finding.get("tags"):
        desc += f"\nTags: {', '.join(finding['tags'][:10])}"
    desc_lines = _wrap_text(desc, 128)
    desc_h = len(desc_lines) * 16 + 22
    full_w = CANVAS_W - MARGIN_X * 2

    elements.append(f'''
        <g transform="translate({MARGIN_X}, {cursor_y})">
            <rect width="{full_w}" height="{desc_h}" rx="5"
                  fill="{pal['desc_bg']}" stroke="{pal['desc_border']}" stroke-width="1"/>''')
    for li, line in enumerate(desc_lines):
        elements.append(f'''
            <text x="12" y="{18 + li * 16}" font-size="11" fill="{pal['desc_text']}"
                  font-family="monospace">{E(line)}</text>''')
    elements.append("</g>")

    cursor_y += desc_h + 20

    svg_html = f'''<svg xmlns="http://www.w3.org/2000/svg"
         width="{CANVAS_W + 40}" height="{cursor_y}"
         viewBox="0 0 {CANVAS_W + 40} {cursor_y}">
        <rect width="100%" height="100%" fill="{pal['canvas_bg']}" rx="6"/>
        {"".join(elements)}
    </svg>'''
    return svg_html


@app.route("/api/findings/<finding_id>/svg", methods=["GET"])
def finding_svg(finding_id):
    try:
        fid = ObjectId(finding_id)
    except Exception:
        return jsonify({"error": "invalid id"}), 400

    doc = findings_col.find_one({"_id": fid})
    if not doc:
        return jsonify({"error": "not found"}), 404

    dark = request.args.get("theme", "dark") != "light"
    svg = render_finding_svg(doc, dark=dark)
    return Response(svg, mimetype="image/svg+xml")


SETTINGS_KEYS = ["snyk_token", "github_token", "semgrep_token"]


@app.route("/api/settings", methods=["GET"])
def get_settings():
    result = {}
    for doc in settings_col.find({"key": {"$in": SETTINGS_KEYS}}):
        key, value = doc["key"], doc.get("value", "")
        if value:
            masked = "\u2022" * 4 + value[-4:] if len(value) > 4 else "\u2022" * len(value)
            result[key] = {"masked": masked, "is_set": True}
        else:
            result[key] = {"masked": "", "is_set": False}
    # Include keys that have no doc yet
    for k in SETTINGS_KEYS:
        if k not in result:
            result[k] = {"masked": "", "is_set": False}
    return jsonify(result)


@app.route("/api/settings", methods=["PUT"])
def put_settings():
    data = request.get_json(force=True) or {}
    for key in SETTINGS_KEYS:
        if key not in data:
            continue
        value = data[key].strip() if isinstance(data[key], str) else ""
        if value:
            settings_col.update_one({"key": key}, {"$set": {"key": key, "value": value}}, upsert=True)
        else:
            settings_col.delete_one({"key": key})
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
