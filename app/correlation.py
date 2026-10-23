"""Conservative correlation of scanner observations into reviewable issues."""

import copy
import hashlib
import json
import posixpath
import re
from urllib.parse import unquote, urlparse
from uuid import uuid4


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def normalize_path(value, repo_dir=""):
    value = unquote(str(value or "")).replace("\\", "/")
    if value.startswith("file://"):
        value = urlparse(value).path
    root = str(repo_dir).replace("\\", "/").rstrip("/")
    if root and value.startswith(root + "/"):
        value = value[len(root) + 1:]
    return posixpath.normpath(value) if value else ""


def normalize_finding(finding, repo_dir=""):
    finding = copy.deepcopy(finding)
    finding["file"] = normalize_path(finding.get("file"), repo_dir)
    for loc in finding.get("all_locations") or []:
        loc["file"] = normalize_path(loc.get("file"), repo_dir)
    for flow in finding.get("code_flows") or []:
        for step in flow:
            step["file"] = normalize_path(step.get("file"), repo_dir)
    finding["cwes"] = sorted({
        "CWE-" + str(int(match.group(1)))
        for tag in (finding.get("cwes") or []) + (finding.get("tags") or [])
        for match in re.finditer(r"(?i)cwe[-/](\d+)", str(tag))
    })
    return finding


def issue_key(finding):
    """Exact evidence only; weak matches get independent issues and suggestions."""
    file = finding.get("file")
    line = finding.get("start_line")
    location = [file, line, finding.get("end_line") or line]
    dependency = finding.get("dependency") or {}
    if all(dependency.get(k) for k in ("vulnerability", "package", "version")) and file:
        return digest(["dependency", file, dependency])
    secret = finding.get("secret_hash")
    if secret and file and line:
        return digest(["secret", location, secret])
    snippet = (finding.get("snippet") or "").strip()
    # Redacted snippets are not evidence that two secrets are equal.
    is_secret = str(finding.get("source_tool", "")).lower() in {"gitleaks", "trufflehog"}
    if file and line and not is_secret:
        flow = [[(s.get("file"), s.get("line"), (s.get("snippet") or "").strip())
                 for s in steps] for steps in finding.get("code_flows") or []]
        columns = [(loc.get("start_col") or 0, loc.get("end_col") or 0)
                   for loc in (finding.get("all_locations") or [])[:1]]
        evidence = [location, columns, snippet, flow]
        if snippet and finding.get("cwes"):
            return digest(["code", finding["cwes"], evidence])
        fingerprints = {k: v for k, v in (finding.get("scanner_fingerprints") or {}).items()
                        if v and str(v).lower() not in {"requires login", "unknown"}}
        fingerprint = finding.get("fingerprint")
        if fingerprint and str(fingerprint).lower() not in {"requires login", "unknown"}:
            fingerprints["primary"] = fingerprint
        if finding.get("rule_id") and finding.get("source_tool") and (snippet or fingerprints):
            return digest(["tool", finding["source_tool"], finding["rule_id"], evidence, fingerprints])
    return "unmatched:" + uuid4().hex


def potential_match(left, right):
    if not left.get("file") or left.get("file") != right.get("file"):
        return False
    if not left.get("start_line") or not right.get("start_line"):
        return False
    return (abs(left["start_line"] - right["start_line"]) <= 3
            and bool(set(left.get("cwes") or []) & set(right.get("cwes") or [])))


def insert_scan_findings(project_id, findings, repo_scope, repo_dir, now):
    from pymongo.errors import DuplicateKeyError
    from db import findings_col, observations_col, projects_col

    inserted = grouped = 0
    for raw in findings:
        finding = normalize_finding(raw, repo_dir)
        key = issue_key(finding)
        query = {"project_id": project_id, "repo_scope": repo_scope, "correlation_key": key}
        tool = finding.get("source_tool") or "Unknown"
        rank = {"error": 4, "warning": 3, "note": 2, "info": 1}.get(finding.get("level"), 0)
        initial = dict(finding, created_at=now, severity_rank=rank, observation_count=0)
        # Mutable summary fields must not overlap $setOnInsert / $addToSet.
        initial.pop("updated_at", None)
        update = {"$setOnInsert": initial, "$set": {"updated_at": now},
                  "$addToSet": {"source_tools": tool}}
        try:
            result = findings_col.update_one(query, update, upsert=True)
        except DuplicateKeyError:
            # Two Gunicorn workers may discover the same issue simultaneously.
            result = findings_col.update_one(query, update)
        issue = findings_col.find_one(query)
        is_new = result.upserted_id is not None
        restored = findings_col.update_one(
            {"_id": issue["_id"], "deleted_at": {"$exists": True}},
            {"$unset": {"deleted_at": ""}}).modified_count
        if is_new or restored:
            inserted += 1
            projects_col.update_one({"_id": project_id}, {"$inc": {"finding_count": 1}})
        else:
            grouped += 1
        # Keep tool-specific details outside the issue document (MongoDB 16 MiB limit).
        observation_key = digest([str(issue["_id"]), finding])
        observation = dict(finding, project_id=project_id, finding_id=issue["_id"], observed_at=now)
        try:
            recorded = observations_col.update_one(
                {"observation_key": observation_key}, {"$setOnInsert": observation}, upsert=True)
            if recorded.upserted_id is not None:
                findings_col.update_one({"_id": issue["_id"]}, {"$inc": {"observation_count": 1}})
        except DuplicateKeyError:
            pass
        findings_col.update_one({"_id": issue["_id"], "severity_rank": {"$lt": rank}},
                                {"$set": {"severity_rank": rank, "level": finding.get("level")}})
        # Compute suggestions independently of arrival order; never auto-merge them.
        if finding.get("file") and finding.get("start_line") and finding.get("cwes"):
            candidates = findings_col.find({
                "project_id": project_id, "repo_scope": repo_scope,
                "file": finding["file"], "_id": {"$ne": issue["_id"]},
                "deleted_at": {"$exists": False},
                "start_line": {"$gte": finding["start_line"] - 3, "$lte": finding["start_line"] + 3},
                "cwes": {"$in": finding["cwes"]},
            })
            for candidate in candidates:
                if potential_match(finding, candidate):
                    findings_col.update_one({"_id": issue["_id"]},
                        {"$addToSet": {"potential_duplicates": str(candidate["_id"])}})
                    findings_col.update_one({"_id": candidate["_id"]},
                        {"$addToSet": {"potential_duplicates": str(issue["_id"])}})
    return inserted, grouped
