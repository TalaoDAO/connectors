from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
import os, base64, json
from typing import Any, Dict, Optional, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from database import db
import copy


class Key(db.Model):
    __bind_key__ = "second"  # this model goes to the second database
    id = db.Column(db.Integer, primary_key=True)
    key_id = db.Column(db.String(128), unique=True)
    key_data = db.Column(db.Text)
    type = db.Column(db.String(128), default="Ed25519")
    created_at = db.Column(db.DateTime, default=datetime.now)


def seed_key():
    try:
        with open('keys.json') as f:
            keys = json.load(f)
        talao_key = copy.copy(keys.get("did:web:talao.co#key-2"))
    except Exception:
        print("key not available in keys.json")
        return
    talao_key.pop("d", None)
    key_data = encrypt_json(talao_key)
    if not Key.query.first():
        key_1 = Key(
            key_id="did:web:talao.co:#key-2",
            key_data=key_data,
            type="P-256"
        )
        db.session.add(key_1)
        
        key_2 = Key(
            key_id="did:cheqd:testnet:1849a6f2-0314-4440-90cb-4700cd8fe0cb#key-1",
            key_data="zy0vUSgs0FBmc4cH7hVgo1d/WVVL0N5unfnT35QpRTPMAQBS3nl+t6zgQU0ZTe05HwuPd56GiwM0Bzgfqgv24wzbPVP2aybGOmXtQS3/rfkB8gq2qwxOno62mGYl3Yt40YHkHkOaOl2P/dsTMFQQt7c8o9vw2ZnsM08VHW5rTzh9dvDEoisJEMZvDsEs0bMsFDsDzh3CiA7QM6zEUbAlclr9iGE3TEHGjW590QSZUPCER/KFClfOVw4KY3g6Osw8Gni2KtCharCO8TjvzO5WhbZEsXTcRoo2jSk0OkXkCGtavA==",
            type="P-256"
        )
        db.session.add(key_2)
        
        db.session.commit()
        print("Talao key has been added to local KMS")
        return


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
