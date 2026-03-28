import hashlib
from datetime import datetime, timezone

from db import findings_col, projects_col

STATUSES = ["new", "confirmed", "false_positive", "mitigated", "accepted_risk"]


def compute_dedup_hash(finding):
    """Compute a deduplication hash for a finding based on its identity fields."""
    key = (
        f"{finding.get('rule_id', '')}:"
        f"{finding.get('file', '')}:"
        f"{finding.get('start_line', 0)}:"
        f"{finding.get('end_line', 0)}:"
        f"{finding.get('snippet', '')}"
    )
    return hashlib.sha256(key.encode()).hexdigest()


def insert_findings_for_project(project_id, findings, fmt, filename="scan"):
    """Insert findings with deduplication. Returns (inserted_count, duplicates_removed)."""
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

    projects_col.update_one({"_id": project_id}, {"$inc": {"finding_count": len(findings)}})

    return len(findings), duplicates_removed


def serialize(doc):
    """Serialize a finding document for JSON response."""
    doc["_id"] = str(doc["_id"])
    doc["project_id"] = str(doc["project_id"])
    if "created_at" in doc:
        doc["created_at"] = doc["created_at"].isoformat()
    if "updated_at" in doc:
        doc["updated_at"] = doc["updated_at"].isoformat()
    return doc


def serialize_project(doc):
    """Serialize a project document for JSON response."""
    doc["_id"] = str(doc["_id"])
    if "uploaded_at" in doc:
        doc["uploaded_at"] = doc["uploaded_at"].isoformat()
    doc.pop("original_sarif", None)
    doc.pop("original_sarifs", None)
    return doc
