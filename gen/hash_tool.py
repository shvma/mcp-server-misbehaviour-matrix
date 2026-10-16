#!/usr/bin/env python3
"""Хеш определения инструмента для поля definition_sha256: python3 gen/hash_tool.py tools/<файл>.json"""
import json
import sys

from defhash import definition_hash

for p in sys.argv[1:]:
    print(definition_hash(json.load(open(p, encoding="utf-8"))), p)
