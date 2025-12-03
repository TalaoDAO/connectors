# tenant_kms.py

import json
import time
import re
import base64
import boto3
from botocore.exceptions import ClientError
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from jwcrypto import jwk, jws 
import logging
from typing import Dict, Any, Tuple, Optional
from kms_model import Key, db, encrypt_json, decrypt_json

REGION = "eu-west-3"   # Paris
KEY_SPEC = "ECC_NIST_P256"  # or "ECC_SECG_P256K1" if you want Ethereum-style keys
KEY_USAGE = "SIGN_VERIFY"
KMS_ADMIN_ROLE_ARN = None

def key_spec_from_verification_method(vm: Dict[str, Any]) -> str:
    """Infer the appropriate KMS KeySpec from a verificationMethod.

    We look first at publicKeyJwk.crv, then fall back to the VM type.
    """
    jwk = vm.get("publicKeyJwk") or {}
    crv = jwk.get("crv")
    if crv == "P-256":
        return "ECC_NIST_P256"
    elif crv == "secp256k1":
        return "ECC_SECG_P256K1"
    elif crv == "Ed25519":
        return "ED25519"

    vm_type = vm.get("type")
    if vm_type == "EcdsaSecp256k1VerificationKey2019":
        return "ECC_SECG_P256K1"

    raise ValueError(f"Cannot infer KeySpec from verificationMethod: {vm}")

def _b64url_decode(data: str) -> bytes:
    """
    Helper to decode base64url (JWK style) with missing padding.
    """
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def kms_init(myenv):
    if myenv == "local":
        BASE_PROFILE = "dev-user"  # the profile you configured via aws
        TARGET_ROLE_ARN = "arn:aws:iam::623031118740:role/my-app-signing-role"
        base_sess = boto3.Session(profile_name=BASE_PROFILE, region_name=REGION)

        sts = base_sess.client("sts")
        resp = sts.assume_role(
            RoleArn=TARGET_ROLE_ARN,
            RoleSessionName="desktop-test-session",
        )
        c = resp["Credentials"]
        assumed_sess = boto3.Session(
            aws_access_key_id=c["AccessKeyId"],
            aws_secret_access_key=c["SecretAccessKey"],
            aws_session_token=c["SessionToken"],
            region_name=REGION,
        )
        manager = TenantKMSManager(boto3_session=assumed_sess, region_name="eu-west-3")
        return manager
    else:
        manager = TenantKMSManager(region_name=REGION)
        return manager


def sanitize_alias_from_did(did_or_vm: str) -> str:
    """
    Sanitize a DID *or* verificationMethod.id into a KMS alias base.

    NOTE:
    - In the new model, we use verificationMethod.id as the alias owner.
    - For legacy DID-level keys, this still works the same.
    """
    body = re.sub(r'[^A-Za-z0-9/_-]', '_', did_or_vm)
    body = body.strip('_')
    body = body[:250]
    return "alias/" + body


def alias_for_tenant(vm_id: str, key_spec: str = None) -> str:
    """
    Build a KMS alias from a tenant identifier (DID or verificationMethod.id),
    optionally namespaced by key_spec.

    - For P-256 (default), we keep 'alias/<sanitized_id>'
    - For secp256k1, we suffix '/secp256k1'
    - This works whether vm_id is the DID or directly the VM id.
    """
    base = sanitize_alias_from_did(vm_id)

    if key_spec is None or key_spec == "ECC_NIST_P256":
        return base

    if key_spec == "ECC_SECG_P256K1":
        return base + "/secp256k1"

    suffix = key_spec.replace("_", "-").lower()
    return f"{base}/{suffix}"


def sanitize_tag_value(value: str) -> str:
    return re.sub(r"[^\w\s\.:\/=\+\-@]", "_", value)


# --- base64url helpers (no padding) ---
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_json(obj: dict) -> str:
    return b64url(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))


# --- map KeySpec <-> JOSE params ---
def _spec_to_alg_and_crv(key_spec: str) -> Tuple[str, str]:
    if key_spec == "ECC_NIST_P256":
        return "ES256", "P-256"
    elif key_spec == "ECC_SECG_P256K1":
        return "ES256K", "secp256k1"
    else:
        raise ValueError(f"Unsupported KeySpec for JWT/JWK: {key_spec}")


def build_initial_policy(app_role_arn: str, account_id: str, admin_role_arn: str = None) -> dict:
    stmts = [
        {
            "Sid": "EnableIAMUserPermissions",
            "Effect": "Allow",
            "Principal": { "AWS": f"arn:aws:iam::{account_id}:root" },
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "AllowAppRoleUseAndPolicyUpdate",
            "Effect": "Allow",
            "Principal": { "AWS": app_role_arn },
            "Action": ["kms:Sign", "kms:GetPublicKey", "kms:Verify", "kms:PutKeyPolicy"],
            "Resource": "*"
        }
    ]
    if admin_role_arn:
        stmts.append({
            "Sid": "AllowAdminToManageKey",
            "Effect": "Allow",
            "Principal": { "AWS": admin_role_arn },
            "Action": ["kms:*"],
            "Resource": "*"
        })
    return {"Version": "2012-10-17", "Id": "key-policy-initial", "Statement": stmts}


def build_final_policy(app_role_arn: str, account_id: str, admin_role_arn: str = None) -> dict:
    stmts = [
        {
            "Sid": "EnableIAMUserPermissions",
            "Effect": "Allow",
            "Principal": { "AWS": f"arn:aws:iam::{account_id}:root" },
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "AllowAppRoleUseOnly",
            "Effect": "Allow",
            "Principal": { "AWS": app_role_arn },
            "Action": ["kms:Sign", "kms:GetPublicKey", "kms:Verify"],
            "Resource": "*"
        }
    ]
    if admin_role_arn:
        stmts.append({
            "Sid": "AllowAdminToManageKey",
            "Effect": "Allow",
            "Principal": { "AWS": admin_role_arn },
            "Action": ["kms:*"],
            "Resource": "*"
        })
    return {"Version": "2012-10-17", "Id": "key-policy-final", "Statement": stmts}


def build_key_policy(app_role_arn: str, account_id: str, admin_role_arn: str = None) -> dict:
    statements = []

    statements.append({
        "Sid": "EnableIAMUserPermissions",
        "Effect": "Allow",
        "Principal": { "AWS": f"arn:aws:iam::{account_id}:root" },
        "Action": "kms:*",
        "Resource": "*"
    })

    if admin_role_arn:
        statements.append({
            "Sid": "AllowAdminToManageKey",
            "Effect": "Allow",
            "Principal": { "AWS": admin_role_arn },
            "Action": [
                "kms:Create*","kms:Describe*","kms:Enable*","kms:List*",
                "kms:PutKeyPolicy","kms:GetKeyPolicy","kms:Update*",
                "kms:TagResource","kms:UntagResource","kms:ScheduleKeyDeletion","kms:CancelKeyDeletion"
            ],
            "Resource": "*"
        })

    statements.append({
        "Sid": "AllowAppRoleUse",
        "Effect": "Allow",
        "Principal": { "AWS": app_role_arn },
        "Action": [
            "kms:Sign",
            "kms:GetPublicKey",
            "kms:Verify"
        ],
        "Resource": "*"
    })

    return {
        "Version": "2012-10-17",
        "Id": "key-policy-tenant-managed-by-app",
        "Statement": statements
    }


# === main class / functions ===

class TenantKMSManager:
    def __init__(self, boto3_session=None, region_name=REGION):
        self.session = boto3_session or boto3.Session(region_name=region_name)
        self.kms = self.session.client("kms", region_name=region_name)
        self.sts = self.session.client("sts", region_name=region_name)

    def get_caller_identity(self):
        return self.sts.get_caller_identity()

    def get_app_role_arn(self):
        ident = self.get_caller_identity()
        return ident.get("Arn"), ident.get("Account")

    def alias_exists(self, alias_name):
        paginator = self.kms.get_paginator("list_aliases")
        for page in paginator.paginate():
            for a in page.get("Aliases", []):
                if a.get("AliasName") == alias_name:
                    return a
        return None

    # -------- core / legacy: tenant-level key (DID) --------

    def create_or_get_key_for_tenant(self, vm_id, description=None, key_spec: str = None):
        if vm_id.startswith("did:cheqd:"):
            # test if it exist
            key_exist = Key.query.filter(Key.key_id == vm_id).one_or_none()
            if key_exist:
                logging.info("Key for cheqd exist")
                return vm_id
            # create a new key
            ed_jwk = jwk.JWK.generate(kty="OKP", crv="Ed25519")
            private_key = ed_jwk.export(private_key=True, as_dict=True)
            private_key["kid"] = ed_jwk.thumbprint()
            key_data = encrypt_json(private_key)
            new_key = Key(
                key_id=vm_id,
                key_data=key_data
            )
            db.session.add(new_key)
            db.session.commit()
            return vm_id
            
        key_spec_to_use = key_spec or KEY_SPEC
        alias_name = alias_for_tenant(vm_id, key_spec_to_use)

        existing_alias = self.alias_exists(alias_name)
        if existing_alias and existing_alias.get("TargetKeyId"):
            logging.info("Alias exists for tenant/key: %s", alias_name)
            return existing_alias["TargetKeyId"]

        app_arn, account_id = self.get_app_role_arn()
        logging.info("App running as ARN: %s", app_arn)

        initial_policy = build_initial_policy(
            app_role_arn=app_arn,
            account_id=account_id,
            admin_role_arn=KMS_ADMIN_ROLE_ARN
        )

        logging.info(
            "Creating KMS key for tenant/key %s with KeySpec=%s",
            vm_id, key_spec_to_use
        )
        resp = self.kms.create_key(
            Policy=json.dumps(initial_policy),
            KeySpec=key_spec_to_use,
            KeyUsage=KEY_USAGE,
            Origin="AWS_KMS",
            Description=(description or f"Tenant key for {vm_id} ({key_spec_to_use})")
        )
        key_id = resp["KeyMetadata"]["KeyId"]
        logging.info("Created key id: %s", key_id)

        final_policy = build_final_policy(
            app_role_arn=app_arn,
            account_id=account_id,
            admin_role_arn=KMS_ADMIN_ROLE_ARN
        )
        self.kms.put_key_policy(
            KeyId=key_id,
            PolicyName="default",
            Policy=json.dumps(final_policy)
        )

        try:
            self.kms.create_alias(AliasName=alias_name, TargetKeyId=key_id)
            logging.info("Created alias: %s", alias_name)
        except ClientError as e:
            logging.warning("create_alias error: %s", str(e))
            existing_alias = self.alias_exists(alias_name)
            if existing_alias and existing_alias.get("TargetKeyId"):
                return existing_alias["TargetKeyId"]
            else:
                raise

        # Tag the key; for VM ids this tag will be the VM id, for DID-level keys it is the DID
        safe_tag = sanitize_tag_value(vm_id)
        try:
            self.kms.tag_resource(
                KeyId=key_id,
                Tags=[{"TagKey": "tenant_did", "TagValue": safe_tag}]
            )
        except Exception as e:
            logging.warning("Warning: failed tagging key: %s", str(e))

        time.sleep(0.5)
        return key_id


    def ensure_alias_for_verification_method(self, vm: Dict[str, Any], key_id: str) -> None:
        """Ensure that there is a KMS alias for this verificationMethod.id.

        This is useful when the key was originally created under an internal
        alias (e.g. an internal vm_id before the final DID was known), and you
        now want to be able to resolve key_id from the public verificationMethod
        in the DID Document.

        If the alias already exists and points to the same key_id, this is a no-op.
        If the alias exists and points to a *different* key, we log a warning
        and do not overwrite it.
        """

        vm_id = vm["id"]
        key_spec = key_spec_from_verification_method(vm)
        alias_name = alias_for_tenant(vm_id, key_spec)

        existing = self.alias_exists(alias_name)
        if existing and existing.get("TargetKeyId"):
            if existing["TargetKeyId"] == key_id:
                # already correct
                return
            # Same alias name but different target: this is suspicious, don't overwrite.
            logging.warning(
                "KMS alias %s already exists and points to a different key (%s != %s)",
                alias_name,
                existing["TargetKeyId"],
                key_id,
            )
            return

        try:
            self.kms.create_alias(AliasName=alias_name, TargetKeyId=key_id)
        except ClientError as e:
            # If another process created it concurrently and it's now correct,
            # we can ignore; otherwise re-raise.
            if e.response.get("Error", {}).get("Code") == "AlreadyExistsException":
                existing = self.alias_exists(alias_name)
                if existing and existing.get("TargetKeyId") == key_id:
                    return
            raise


    def create_or_get_key_for_verification_method(self, vm_id: str, key_spec: str) -> str:
        """
        Create or fetch a KMS key for a specific verificationMethod.id.

        This is the recommended way to manage keys when a DID has multiple VMs.
        """
        return self.create_or_get_key_for_tenant(vm_id, key_spec=key_spec)


    def get_key_id_for_verification_method(self, vm: Dict[str, Any]) -> str:
        """
        Resolve the KMS key_id for a verificationMethod from a DID Document.

        Expects:
          - vm["id"]  (verificationMethod.id)
          - vm["publicKeyJwk"]["crv"] or a known 'type' to infer KeySpec
        """
        vm_id = vm["id"]
        if vm_id.startswith("did:cheqd"):
            return vm_id
        
        key_spec = key_spec_from_verification_method(vm)
        alias_name = alias_for_tenant(vm_id, key_spec)
        md = self.kms.describe_key(KeyId=alias_name)
        return md["KeyMetadata"]["KeyId"]

    # -------- utilities: public key & signatures --------

    def get_public_key_pem(self, key_id):
        resp = self.kms.get_public_key(KeyId=key_id)
        der = resp["PublicKey"]
        pubkey = load_der_public_key(der)
        pem = pubkey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        return pem.decode(), pubkey

    def get_public_key_jwk(self, key_id):
        # check for local key
        key_in_db = Key.query.filter(Key.key_id == key_id).one_or_none()
        if key_in_db:
            key = decrypt_json(key_in_db.key_data)
            key.pop("d")
            return key, key["kid"], "EdDSA"
            
        md = self.kms.describe_key(KeyId=key_id)["KeyMetadata"]
        key_spec = md["KeySpec"]
        alg, crv = _spec_to_alg_and_crv(key_spec)

        resp = self.kms.get_public_key(KeyId=key_id)
        der = resp["PublicKey"]
        pubkey = load_der_public_key(der)

        if not isinstance(pubkey, ec.EllipticCurvePublicKey):
            raise ValueError("KMS public key is not EC")

        numbers = pubkey.public_numbers()
        x_bytes = numbers.x.to_bytes(32, "big")
        y_bytes = numbers.y.to_bytes(32, "big")

        jwk = {
            "kty": "EC",
            "crv": crv,
            "x": b64url(x_bytes),
            "y": b64url(y_bytes),
        }

        thumb_input = json.dumps(
            {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
            separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        kid = b64url(hashlib.sha256(thumb_input).digest())

        return jwk, kid, alg

    def sign_message(self, key_id, message_bytes: bytes, local=False) -> Tuple[bytes, Tuple[int, int]]:
        digest = hashlib.sha256(message_bytes).digest()
        
        if key_id.startswith("did:cheqd:"):
            # --- Local Ed25519 path using jwcrypto ---
            key_in_db = Key.query.filter(Key.key_id == key_id).one_or_none()
            if key_in_db is None:
                raise ValueError(f"No local key found for key_id={key_id}")

            # decrypt_json should return the JWK (dict or JSON string)
            jwk_data = decrypt_json(key_in_db.key_data)
            jwk_json = json.dumps(jwk_data)
            jwk_key = jwk.JWK.from_json(jwk_json)

            # Export full JWK and pull out the private component "d"
            full_jwk = json.loads(jwk_key.export(private_key=True))
            priv_bytes = _b64url_decode(full_jwk["d"])

            # Build an Ed25519 private key from the raw private key bytes
            private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)

            # Ed25519 signs the *raw* message (no external hashing)
            signature = private_key.sign(message_bytes)  # 64 bytes

            return signature, ("", "")
    
        resp = self.kms.sign(
            KeyId=key_id,
            Message=digest,
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        signature = resp["Signature"]
        r, s = decode_dss_signature(signature)
        return signature, (r, s)

    
    def sign_jwt_with_key(self, key_id, header: dict, payload: dict, local: bool = False) -> str:
        """
        Sign a JWT with either:
        - a local Ed25519 key stored in the DB (local=True, alg=EdDSA), or
        - an EC key in AWS KMS (local=False, alg=ES256/ES256K).

        key_id:
        - local=True  -> DID / verificationMethod.id used as Key.key_id
        - local=False -> KMS key id or alias
        """
        # --- Figure out alg & JWK (works for both local and KMS) ---
        jwk_dict, kid, alg_from_key = self.get_public_key_jwk(key_id)

        # Header defaults
        if "alg" not in header:
            header["alg"] = alg_from_key  # "EdDSA" for local Ed25519, ES256/ES256K for KMS
        header.setdefault("typ", "JWT")
        # You can also set kid if you want:
        # header.setdefault("kid", kid)

        # --- Build signing input ---
        encoded_header = b64url_json(header)
        encoded_payload = b64url_json(payload)
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")

        # --- Local Ed25519 path (EdDSA) ---
        if key_id.startswith("did:cheqd"):
            # sign_message() will use the local Ed25519 key when local=True
            signature, _ = self.sign_message(key_id, signing_input, local=True)

            # For EdDSA/Ed25519, JOSE signature is just the 64 raw bytes, base64url-encoded
            jose_sig = b64url(signature)

            return f"{encoded_header}.{encoded_payload}.{jose_sig}"

        # --- KMS EC path (ES256 / ES256K) ---
        # Still use describe_key for EC KMS keys if you need the KeySpec; not strictly required
        md = self.kms.describe_key(KeyId=key_id)["KeyMetadata"]
        key_spec = md["KeySpec"]
        alg, _crv = _spec_to_alg_and_crv(key_spec)  # kept for sanity/logging; header["alg"] already set

        der_sig, (r, s) = self.sign_message(key_id, signing_input)

        # Convert DER ECDSA sig to JOSE format: r || s (32 bytes each, big-endian)
        r_bytes = r.to_bytes(32, "big")
        s_bytes = s.to_bytes(32, "big")
        jose_sig = b64url(r_bytes + s_bytes)

        return f"{encoded_header}.{encoded_payload}.{jose_sig}"


    # === convenience: DID-level signing (legacy) ===

    def sign_jwt_for_tenant(self, tenant_did: str, header: dict, payload: dict) -> str:
        """
        Legacy convenience: treat the DID as the tenant identifier and
        sign with its *default* key (P-256).

        For multiple verificationMethods, prefer:
          - create_or_get_key_for_verification_method(vm_id, key_spec)
          - sign_jwt_with_key(key_id, ...)
        """
        alias_name = sanitize_alias_from_did(tenant_did)
        md = self.kms.describe_key(KeyId=alias_name)
        key_id = md["KeyMetadata"]["KeyId"]
        return self.sign_jwt_with_key(key_id, header, payload)


    def verify_tenant_jwt_with_jwcrypto(self, tenant_did: str, jwt_compact: str):
        """
        Legacy convenience: resolve DID-level alias -> key -> JWK, then verify JWT.

        For multiple verificationMethods, prefer using get_key_id_for_verification_method()
        and verify_jwt_with_jwcrypto() directly.
        """
        alias = sanitize_alias_from_did(tenant_did)
        md = self.kms.describe_key(KeyId=alias)
        key_id = md["KeyMetadata"]["KeyId"]
        jwk, kid, alg = self.get_public_key_jwk(key_id)
        return verify_jwt_with_jwcrypto(jwt_compact, jwk)


# --- JWS verification with jwcrypto ---

def verify_jwt_with_jwcrypto(jwt_compact: str, jwk_dict: dict):
    key = jwk.JWK.from_json(json.dumps(jwk_dict))
    token = jws.JWS()
    token.deserialize(jwt_compact)

    try:
        token.verify(key)
    except NotImplementedError as e:
        raise RuntimeError(
            "Your jwcrypto/cryptography build doesn't support the JWT alg in the header "
            "(likely ES256K). Upgrade jwcrypto & cryptography, or verify via cryptography manually."
        ) from e

    header = json.loads(token.jose_header) if isinstance(token.jose_header, str) else token.jose_header
    payload = json.loads(token.payload.decode("utf-8"))
    return header, payload


# === simple demo ===
def test_flow(tenant_did: str):
    manager = kms_init("local")
    key_id = manager.create_or_get_key_for_tenant(tenant_did)
    print("Key available:", key_id)

    pem, pubkey = manager.get_public_key_pem(key_id)
    print("Public key PEM:\n", pem)

    message = f"POC signing for tenant {tenant_did}"
    sig, (r, s) = manager.sign_message(key_id, message.encode("utf-8"))
    print("Signature (base64):", base64.b64encode(sig).decode())
    print("r:", r)
    print("s:", s)


if __name__ == "__main__":
    demo_did = "did:web:wallet4agent.com:demo#key-1"
    # test_flow(demo_did)
    manager = kms_init("local")
    print("Demo OK, KMS manager initialised.")
