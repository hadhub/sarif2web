import re
from datetime import datetime, timezone

from bson import ObjectId
from flask import Blueprint, Response, jsonify, request

from db import findings_col, observations_col, projects_col
from helpers import STATUSES, serialize
from svg import render_finding_svg

bp = Blueprint("findings", __name__)


@bp.route("/api/findings", methods=["GET"])
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
        query["$and"] = [{"$or": [{"source_tools": {"$in": tool.split(",")}},
                                    {"source_tool": {"$in": tool.split(",")}}]}]

    search = request.args.get("q", "").strip()[:256]
    if search:
        escaped = re.escape(search)
        query["$or"] = [
            {"rule_id": {"$regex": escaped, "$options": "i"}},
            {"file": {"$regex": escaped, "$options": "i"}},
            {"message": {"$regex": escaped, "$options": "i"}},
            {"snippet": {"$regex": escaped, "$options": "i"}},
            {"_id": ObjectId(search)} if ObjectId.is_valid(search) else {"source_tools": search},
        ]

    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        per_page = min(500, max(1, int(request.args.get("per_page", 100))))
    except (ValueError, TypeError):
        per_page = 100

    cursor = findings_col.find(query).sort([("level", 1), ("rule_id", 1)])
    total = findings_col.count_documents(query)
    docs = list(cursor.skip((page - 1) * per_page).limit(per_page))

    # Potential links may outlive a deletion; only expose active targets.
    candidate_ids = {ObjectId(i) for d in docs for i in d.get("potential_duplicates", []) if ObjectId.is_valid(i)}
    active = {str(d["_id"]) for d in findings_col.find(
        {"_id": {"$in": list(candidate_ids)}, "project_id": pid, "deleted_at": {"$exists": False}}, {"_id": 1})} if candidate_ids else set()
    for d in docs:
        d["potential_duplicates"] = [i for i in d.get("potential_duplicates", []) if i in active]
    return jsonify({
        "findings": [serialize(d) for d in docs],
        "total": total,
        "page": page,
        "per_page": per_page,
    })


@bp.route("/api/findings/counts", methods=["GET"])
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
        total += c

    for doc in findings_col.aggregate([
        {"$match": {"project_id": pid, "deleted_at": {"$exists": False}}},
        {"$project": {"tools": {"$ifNull": ["$source_tools", ["$source_tool"]]}}},
        {"$unwind": "$tools"}, {"$group": {"_id": "$tools", "count": {"$sum": 1}}},
    ]):
        tools[doc["_id"] or "Unknown"] = doc["count"]

    return jsonify({"levels": levels, "statuses": statuses, "tools": tools, "total": total})


@bp.route("/api/findings/<finding_id>/observations", methods=["GET"])
def finding_observations(finding_id):
    if not ObjectId.is_valid(finding_id):
        return jsonify({"error": "invalid id"}), 400
    fid = ObjectId(finding_id)
    issue = findings_col.find_one({"_id": fid, "deleted_at": {"$exists": False}})
    if not issue:
        return jsonify({"error": "not found"}), 404
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    docs = list(observations_col.find({"finding_id": fid}).sort("observed_at", -1)
                .skip((page - 1) * 50).limit(50))
    for d in docs:
        d["finding_id"] = str(d["finding_id"])
        d["observed_at"] = d["observed_at"].isoformat()
        d.pop("secret_hash", None)
    return jsonify({"observations": [serialize(d) for d in docs], "page": page,
                    "total": observations_col.count_documents({"finding_id": fid})})


@bp.route("/api/findings/<finding_id>", methods=["PATCH"])
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


@bp.route("/api/findings/bulk", methods=["PATCH"])
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


@bp.route("/api/findings/bulk-delete", methods=["POST"])
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

    result = findings_col.update_many(
        {"_id": {"$in": oids}, "deleted_at": {"$exists": False}},
        {"$set": {"deleted_at": now}},
    )

    affected = list(findings_col.find({"_id": {"$in": oids}, "deleted_at": now}, {"project_id": 1}))
    project_counts = {}
    for doc in affected:
        pid = doc["project_id"]
        project_counts[pid] = project_counts.get(pid, 0) + 1
    for pid, count in project_counts.items():
        projects_col.update_one({"_id": pid}, {"$inc": {"finding_count": -count}})

    return jsonify({"ok": True, "deleted": result.modified_count, "ids": [str(o) for o in oids]})


@bp.route("/api/findings/restore", methods=["POST"])
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

    affected = list(findings_col.find({"_id": {"$in": oids}, "deleted_at": {"$exists": True}}, {"project_id": 1}))
    project_counts = {}
    for doc in affected:
        pid = doc["project_id"]
        project_counts[pid] = project_counts.get(pid, 0) + 1

    result = findings_col.update_many(
        {"_id": {"$in": oids}, "deleted_at": {"$exists": True}},
        {"$unset": {"deleted_at": ""}},
    )

    for pid, count in project_counts.items():
        projects_col.update_one({"_id": pid}, {"$inc": {"finding_count": count}})

    return jsonify({"ok": True, "restored": result.modified_count})


@bp.route("/api/findings/<finding_id>/svg", methods=["GET"])
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
