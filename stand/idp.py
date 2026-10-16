#!/usr/bin/env python3
"""Учебный издатель токенов для стенда (вместо Keycloak). Подпись RS256 через openssl.

  python3 stand/idp.py keygen DIR            -> DIR/key.pem (секрет), DIR/jwks.json (открытый ключ)
  python3 stand/idp.py token DIR SUB [секунд_жизни] [aud]   -> JWT в stdout

Приватный ключ живёт только на стенде и в git не попадает (stand/idp/ в .gitignore).
"""
import base64
import json
import subprocess
import sys
import time
from pathlib import Path

ISSUER = "stand-idp"
AUDIENCE = "admission-gateway"
KID = "stand-1"


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def keygen(d):
    d.mkdir(parents=True, exist_ok=True)
    key = d / "key.pem"
    subprocess.run(["openssl", "genrsa", "-out", str(key), "2048"], check=True, capture_output=True)
    key.chmod(0o600)
    mod = subprocess.run(["openssl", "rsa", "-in", str(key), "-noout", "-modulus"],
                         check=True, capture_output=True, text=True).stdout.strip().split("=", 1)[1]
    jwk = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID,
           "n": b64url(bytes.fromhex(mod)), "e": b64url((65537).to_bytes(3, "big"))}
    (d / "jwks.json").write_text(json.dumps({"keys": [jwk]}))


def token(d, sub, ttl=300, aud=AUDIENCE):
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": KID}
    payload = {"iss": ISSUER, "aud": aud, "sub": sub, "iat": now, "exp": now + int(ttl)}
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}"
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(d / "key.pem")],
                         input=signing_input.encode(), check=True, capture_output=True).stdout
    return f"{signing_input}.{b64url(sig)}"


if __name__ == "__main__":
    cmd, d = sys.argv[1], Path(sys.argv[2])
    if cmd == "keygen":
        keygen(d)
    elif cmd == "token":
        print(token(d, sys.argv[3], *(sys.argv[4:6])))
