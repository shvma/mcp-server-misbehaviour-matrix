"""SHA-256 of a canonical MCP tool definition. Shared by the policy data and the decision service."""
import hashlib
import json


def definition_hash(defn):
    canon = json.dumps(defn, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()
