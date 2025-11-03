# deterministic_keys.py
import base64
import json
import hmac
import hashlib
from typing import Optional, Dict, Any

from jwcrypto import jwk
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from argon2.low_level import hash_secret_raw, Type as Argon2Type


# ---------- helpers ----------

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def _derive_salt_from_pepper(pepper: bytes, context: bytes) -> bytes:
    """Secret salt derived deterministically from a secret pepper + context label."""
    return hmac.new(pepper, context, hashlib.sha256).digest()  # 32 bytes

def _kdf_seed(passphrase: str, salt: bytes) -> bytes:
    """
    Derive `preferred_len` bytes deterministically from passphrase and salt.
    Uses Argon2id.
    """
    time_cost = 3
    memory_cost_kib = 65536  # 64 MiB
    parallelism = 1
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost_kib,
        parallelism=parallelism,
        hash_len=32,
        type=Argon2Type.ID,
    )

def _int_to_fixed(n: int, length: int) -> bytes:
    return n.to_bytes(length, byteorder="big")

def _ec_derive_private_key_from_seed(seed32: bytes, curve: ec.EllipticCurve) -> ec.EllipticCurvePrivateKey:
    """
    Map 32-byte seed -> valid private scalar for the given curve:
        d = (seed % (n-1)) + 1
    and use cryptography's derive_private_key.
    """
    if len(seed32) != 32:
        raise ValueError("seed32 must be 32 bytes")
    # Order for P-256 (secp256r1)
    if isinstance(curve, ec.SECP256R1):
        n = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    else:
        raise ValueError("Unsupported curve")

    d = (int.from_bytes(seed32, "big") % (n - 1)) + 1
    return ec.derive_private_key(d, curve)


# ---------- JWK builders ----------

def jwk_ed25519_from_passphrase(passphrase: str, context: bytes = b"myapp:ed25519:v1") -> jwk.JWK:
    """Deterministic Ed25519 private JWK requiring passphrase + secret pepper."""
    with open("keys.json", "r") as f:
        keys = json.load(f)
    pepper = base64.b64decode(keys["pepper"])
    salt = _derive_salt_from_pepper(pepper, context)
    seed = _kdf_seed(passphrase, salt)

    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    jwk_dict = {
        "kty": "OKP",
        "crv": "Ed25519",
        "d": _b64url(seed),
        "x": _b64url(pub_bytes),
    }
    return jwk_dict


def jwk_p256_from_passphrase(passphrase: str, context: bytes = b"myapp:p256:v1") -> jwk.JWK:
    """Deterministic P-256 (secp256r1) private JWK requiring passphrase + secret pepper."""
    with open("keys.json", "r") as f:
        keys = json.load(f)
    pepper = base64.b64decode(keys["pepper"])
    salt = _derive_salt_from_pepper(pepper, context)
    seed = _kdf_seed(passphrase, salt)

    priv = _ec_derive_private_key_from_seed(seed, ec.SECP256R1())
    numbers = priv.private_numbers()
    pub_nums = numbers.public_numbers

    # 32-byte fixed field size for P-256 coordinates and private scalar
    d_b = _int_to_fixed(numbers.private_value, 32)
    x_b = _int_to_fixed(pub_nums.x, 32)
    y_b = _int_to_fixed(pub_nums.y, 32)

    jwk_dict = {
        "kty": "EC",
        "crv": "P-256",
        "d": _b64url(d_b),
        "x": _b64url(x_b),
        "y": _b64url(y_b),
    }
    return jwk_dict


# ---------- example usage ----------

if __name__ == "__main__":
    # NEVER hardcode your pepper in real code: fetch from your secret manager / HSM.
    
    passphrase = "publicly-known-passphrase-or-user-supplied"

    ed_jwk = jwk_ed25519_from_passphrase(passphrase)
    p256_jwk = jwk_p256_from_passphrase(passphrase)

    print("Ed25519 (private) JWK:\n", ed_jwk.export(private_key=True))
    print("\nP-256 (private) JWK:\n", p256_jwk.export(private_key=True))
