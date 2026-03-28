import json

from bson import ObjectId
from flask import Blueprint, Response, jsonify, request

from db import findings_col, projects_col
from helpers import insert_findings_for_project
from parsers import detect_format, parse_gitleaks, parse_sarif, parse_trufflehog

bp = Blueprint("upload", __name__)


ALLOWED_EXTENSIONS = {"sarif", "json", "jsonl"}


@bp.route("/api/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "no file"}), 400

    # Validate file extension
    ext = (f.filename or "").rsplit(".", 1)[-1].lower() if "." in (f.filename or "") else ""
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"error": f"unsupported file extension (allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))})"}), 400

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
        raw_text = f.read().decode("utf-8")
    except UnicodeDecodeError:
        return jsonify({"error": "file must be valid UTF-8"}), 400
    except Exception:
        return jsonify({"error": "cannot read file"}), 400

    if not raw_text.strip():
        return jsonify({"error": "file is empty"}), 400

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


@bp.route("/api/export/<project_id>", methods=["GET"])
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

    original_sarifs = project.get("original_sarifs", [])
    old_sarif = project.get("original_sarif")

    if original_sarifs:
        merged = {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json", "version": "2.1.0", "runs": []}
        for entry in original_sarifs:
            data = entry.get("data", {})
            if isinstance(data, dict) and "runs" in data:
                inject_review(data)
                merged["runs"].extend(data["runs"])
            else:
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
