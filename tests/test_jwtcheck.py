"""Offline unit tests for lib/jwtcheck.py — it sits on the trust path (billing, typed adapter).

No network and no Keycloak: the test generates its own RSA key and injects the public key
into the module's JWKS cache, so _key() never fetches. Each failure reason verify() promises
gets a test, plus the valid path and peek().
"""
import base64
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402

import jwtcheck  # noqa: E402

KID = "test-key"


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_token(key, claims, alg="RS256", kid=KID):
    header = b64u(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}).encode())
    payload = b64u(json.dumps(claims).encode())
    sig = key.sign(f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{b64u(sig)}"


def valid_claims(**overrides):
    claims = {"iss": jwtcheck.ISSUER, "exp": int(time.time()) + 300, "aud": "notes"}
    claims.update(overrides)
    return claims


class JwtCheckTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        # Pre-seed the cache so _key(KID) returns our public key and never hits the network.
        jwtcheck._keys = {KID: self.key.public_key()}

    def test_valid_returns_claims(self):
        claims = jwtcheck.verify(make_token(self.key, valid_claims(sub="u1")), "notes")
        self.assertEqual(claims["sub"], "u1")

    def test_malformed(self):
        with self.assertRaises(ValueError) as e:
            jwtcheck.verify("not-a-jwt", "notes")
        self.assertEqual(str(e.exception), "malformed")

    def test_wrong_alg_rejected(self):
        # alg is checked before the signature, so the RSA signature here is irrelevant.
        with self.assertRaises(ValueError) as e:
            jwtcheck.verify(make_token(self.key, valid_claims(), alg="HS256"), "notes")
        self.assertEqual(str(e.exception), "alg")

    def test_bad_signature_rejected(self):
        # Signed by a key that is not the one in the cache.
        with self.assertRaises(ValueError) as e:
            jwtcheck.verify(make_token(self.other, valid_claims()), "notes")
        self.assertEqual(str(e.exception), "signature")

    def test_wrong_issuer_rejected(self):
        with self.assertRaises(ValueError) as e:
            jwtcheck.verify(make_token(self.key, valid_claims(iss="http://evil/realms/x")), "notes")
        self.assertEqual(str(e.exception), "issuer")

    def test_expired_rejected(self):
        with self.assertRaises(ValueError) as e:
            jwtcheck.verify(make_token(self.key, valid_claims(exp=int(time.time()) - 1)), "notes")
        self.assertEqual(str(e.exception), "expired")

    def test_wrong_audience_rejected(self):
        with self.assertRaises(ValueError) as e:
            jwtcheck.verify(make_token(self.key, valid_claims(aud="billing")), "notes")
        self.assertEqual(str(e.exception), "audience")

    def test_audience_list_accepted(self):
        claims = jwtcheck.verify(make_token(self.key, valid_claims(aud=["billing", "notes"])), "notes")
        self.assertIn("notes", claims["aud"])

    def test_peek_returns_unverified_claims(self):
        # peek ignores the signature on purpose (trace only); a badly signed token still reads.
        self.assertEqual(jwtcheck.peek(make_token(self.other, valid_claims(sub="x")))["sub"], "x")

    def test_peek_garbage_returns_empty(self):
        self.assertEqual(jwtcheck.peek("garbage"), {})


if __name__ == "__main__":
    unittest.main()
