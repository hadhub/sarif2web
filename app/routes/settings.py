from flask import Blueprint, jsonify, request

from crypto import decrypt, encrypt
from db import settings_col
from scanner import SETTINGS_KEYS

bp = Blueprint("settings", __name__)


@bp.route("/api/settings", methods=["GET"])
def get_settings():
    result = {}
    for doc in settings_col.find({"key": {"$in": SETTINGS_KEYS}}):
        key = doc["key"]
        raw = doc.get("value", "")
        # Try to decrypt; if it fails, treat as legacy plaintext
        value = decrypt(raw) if raw else ""
        if value:
            masked = "\u2022" * 4 + value[-4:] if len(value) > 4 else "\u2022" * len(value)
            result[key] = {"masked": masked, "is_set": True}
        else:
            result[key] = {"masked": "", "is_set": False}
    for k in SETTINGS_KEYS:
        if k not in result:
            result[k] = {"masked": "", "is_set": False}
    return jsonify(result)


@bp.route("/api/settings", methods=["PUT"])
def put_settings():
    data = request.get_json(force=True) or {}
    for key in SETTINGS_KEYS:
        if key not in data:
            continue
        value = data[key].strip() if isinstance(data[key], str) else ""
        if value:
            encrypted = encrypt(value)
            settings_col.update_one({"key": key}, {"$set": {"key": key, "value": encrypted}}, upsert=True)
        else:
            settings_col.delete_one({"key": key})
    return jsonify({"ok": True})
