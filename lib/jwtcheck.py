"""JWT verification against the testbed Keycloak: RS256 signature from JWKS, issuer, expiry, audience.
Used by billing and by the typed adapter; it sits on the trust path, so it stays minimal."""
import base64
import json
import time
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ISSUER = "http://localhost:8080/realms/stand"
JWKS_URL = ISSUER + "/protocol/openid-connect/certs"
_keys = {}


def _b64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _key(kid):
    if kid not in _keys:
        with urllib.request.urlopen(JWKS_URL, timeout=3) as r:
            for k in json.load(r)["keys"]:
                if k.get("kty") == "RSA" and k.get("use", "sig") == "sig":
                    n, e = (int.from_bytes(_b64(k[x]), "big") for x in ("n", "e"))
                    _keys[k["kid"]] = rsa.RSAPublicNumbers(e, n).public_key()
    return _keys[kid]


def verify(token, audience):
    """Return the claims if the token is valid for `audience`; otherwise raise ValueError(reason)."""
    try:
        h, p, s = token.split(".")
        header, claims = json.loads(_b64(h)), json.loads(_b64(p))
    except Exception:
        raise ValueError("malformed")
    if header.get("alg") != "RS256":
        raise ValueError("alg")
    try:
        _key(header.get("kid")).verify(_b64(s), f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        raise ValueError("signature")
    if claims.get("iss") != ISSUER:
        raise ValueError("issuer")
    if claims.get("exp", 0) < time.time():
        raise ValueError("expired")
    aud = claims.get("aud")
    if audience not in (aud if isinstance(aud, list) else [aud]):
        raise ValueError("audience")
    return claims


def peek(token):
    """Unverified claims, for trace records only. Never used for a decision."""
    try:
        return json.loads(_b64(token.split(".")[1]))
    except Exception:
        return {}
