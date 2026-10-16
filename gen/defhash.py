"""Хеш определения MCP-инструмента. Один код на генератор и адаптер, иначе хеши разъедутся."""
import hashlib
import json


def definition_hash(defn):
    canon = json.dumps(defn, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()
