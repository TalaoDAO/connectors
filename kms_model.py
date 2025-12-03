from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
import os, base64, json
from typing import Any, Dict, Optional, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from database import db


class Key(db.Model):
    __bind_key__ = "second"  # this model goes to the second database
    id = db.Column(db.Integer, primary_key=True)
    key_id = db.Column(db.String(128))
    key_data = db.Column(db.Text)
    type = db.Column(db.String(128), default="Ed25519")
    created_at = db.Column(db.DateTime, default=datetime.now)


def seed_key():
    if not Key.query.first():
        key = Key(
            key_id="did:cheqd:testnet:209779d5-708b-430d-bb16-fba6407cd1ac",
            key_data="K3P4+sYmUX0ltDDwCIbMC4ulE6szPwBjTAxQJgJ+kTBPh9RZj0MnuMAoJmBqn6koq+rtl5A9NTFbQ+msGGiM7Ka8HNq8UCBPoJwk1yrYzRjD3rGz2PJyBO0KZrEeuYWvUH/9IdJDGHQUuldDUC67wvukI7aWkZl+7eD0o3ARYfMTMMeqqB6+O4Ps5p3pDnzJEN778hfv/E9VrPWrZ3Nt5SA6O4TBlmFbAKUXoZ2EGpfdxmp8g0YvhJIemOvqVnoqVosOBMe3kXAfkeNjEPClVlE=",
            type="Ed25519"
        )
        db.session.add(key)


def load_keys() -> bytes:
    try:
        with open('keys.json') as f:
            keys = json.load(f)
        kms_key =  keys.get("kms_key")
    except Exception:
        return
    return base64.b64decode(kms_key)


KEY = load_keys()

def encrypt_bytes(plaintext: bytes, aad: Optional[bytes] = None) -> str:
    """
    AES-GCM avec nonce aléatoire (12 bytes). Return base64(nonce || ciphertext).
    """
    aes = AESGCM(KEY)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, aad)
    blob = nonce + ct
    return base64.b64encode(blob).decode()

def decrypt_bytes(blob_b64: str, aad: Optional[bytes] = None) -> bytes:
    """
    blob = base64(nonce||ciphertext)
    """
    blob = base64.b64decode(blob_b64)
    nonce, ct = blob[:12], blob[12:]
    try:
        return AESGCM(KEY).decrypt(nonce, ct, aad)
    except Exception:
        raise ValueError("Déchiffrement impossible (clé invalide ?)")

# Helpers JSON pratiques
def encrypt_json(data: Dict[str, Any]) -> str:
    if not data:
        return
    return encrypt_bytes(json.dumps(data, separators=(",", ":")).encode())

def decrypt_json(blob_b64: str) -> Dict[str, Any]:
    if not blob_b64:
        return
    return json.loads(decrypt_bytes(blob_b64).decode())
