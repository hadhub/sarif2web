import os

from pymongo import MongoClient

client = MongoClient(os.environ.get("MONGO_URI", "mongodb://localhost:27017/sarif_manager"))
db = client.get_default_database()

projects_col = db["projects"]
findings_col = db["findings"]
scans_col = db["scans"]
settings_col = db["settings"]
semgrep_rules_col = db["semgrep_rules"]
observations_col = db["observations"]

# Ensure index for fast per-project duplicate lookups
findings_col.create_index([("project_id", 1), ("dedup_hash", 1)])
findings_col.create_index([("project_id", 1), ("repo_scope", 1), ("correlation_key", 1)],
                         unique=True, partialFilterExpression={"correlation_key": {"$type": "string"}})
findings_col.create_index([("project_id", 1), ("repo_scope", 1), ("file", 1), ("start_line", 1)])
observations_col.create_index("observation_key", unique=True)
observations_col.create_index([("finding_id", 1), ("observed_at", -1)])
