# tenant_kms.py

import json
import time
import re
import base64
import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import hashlib
from jwcrypto import jwk as _jwk, jws as _jws
import json as _json
import logging


REGION = "eu-west-3"   # Paris
KEY_SPEC = "ECC_NIST_P256"  # or "ECC_SECG_P256K1" if you want Ethereum-style keys
KEY_USAGE = "SIGN_VERIFY"
KMS_ADMIN_ROLE_ARN = None


def kms_init(myenv):
    
    if myenv == "local":
        
        BASE_PROFILE = "dev-user"  # the profile you configured via aws
        TARGET_ROLE_ARN = "arn:aws:iam::623031118740:role/my-app-signing-role"
        base_sess = boto3.Session(profile_name=BASE_PROFILE, region_name=REGION)

        #logging.info("Base identity: %s", json.dumps(base_sess.client("sts").get_caller_identity(), indent=2))

        # 2) assume the application role using the SAME session
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
        #logging.info("Assumed identity: %s", json.dumps(assumed_sess.client("sts").get_caller_identity(), indent=2))
        manager = TenantKMSManager(boto3_session=assumed_sess, region_name="eu-west-3")
        return manager
    else:
        manager = TenantKMSManager(region_name=REGION)
        return manager
    



def sanitize_alias_from_did(did: str) -> str:
    # Allow only A–Z a–z 0–9 / _ -
    body = re.sub(r'[^A-Za-z0-9/_-]', '_', did)
    body = body.strip('_')
    # keep total length within KMS limits
    body = body[:250]
    return "alias/" + body


def sanitize_tag_value(value: str) -> str:
    # Allow only valid AWS tag characters: [\p{L}\p{Z}\p{N}_.:/=+\-@]
    return re.sub(r"[^\w\s\.:\/=\+\-@]", "_", value)


# --- base64url helpers (no padding) ---
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_json(obj: dict) -> str:
    return b64url(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))


# --- map KeySpec <-> JOSE params ---
def _spec_to_alg_and_crv(key_spec: str):
    if key_spec == "ECC_NIST_P256":
        return "ES256", "P-256"
    elif key_spec == "ECC_SECG_P256K1":
        # widely used in DID / Web3 JWTs
        return "ES256K", "secp256k1"
    else:
        raise ValueError(f"Unsupported KeySpec for JWT/JWK: {key_spec}")


def build_initial_policy(app_role_arn: str, account_id: str, admin_role_arn: str = None) -> dict:
    stmts = [
        {  # root admin so someone can always recover/manage
            "Sid": "EnableIAMUserPermissions",
            "Effect": "Allow",
            "Principal": { "AWS": f"arn:aws:iam::{account_id}:root" },
            "Action": "kms:*",
            "Resource": "*"
        },
        {  # app role: allow usage + PutKeyPolicy temporarily
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

    # 1) REQUIRED: enable account-level admin via the root principal (KMS default pattern)
    statements.append({
        "Sid": "EnableIAMUserPermissions",
        "Effect": "Allow",
        "Principal": { "AWS": f"arn:aws:iam::{account_id}:root" },
        "Action": "kms:*",
        "Resource": "*"
    })

    # 2) Optional: narrow admin role (if you have one)
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

    # 3) App role: only usage permissions
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
        # KMS list_aliases returns up to 100 items; do a paginated search
        paginator = self.kms.get_paginator("list_aliases")
        for page in paginator.paginate():
            for a in page.get("Aliases", []):
                if a.get("AliasName") == alias_name:
                    return a
        return None

    def create_or_get_key_for_tenant(self, tenant_did, description=None):
        alias_name = sanitize_alias_from_did(tenant_did)
        # if alias already exists, return its TargetKeyId
        existing_alias = self.alias_exists(alias_name)
        if existing_alias and existing_alias.get("TargetKeyId"):
            logging.info("Alias exists for tenant: %s", alias_name)
            return existing_alias["TargetKeyId"]

        app_arn, account_id = self.get_app_role_arn()
        logging.info("App running as ARN: %s", app_arn)

        initial_policy = build_initial_policy(app_role_arn=app_arn, account_id=account_id, admin_role_arn=KMS_ADMIN_ROLE_ARN)

        logging.info("Creating KMS key for tenant: %s", tenant_did)
        resp = self.kms.create_key(
            Policy=json.dumps(initial_policy),
            KeySpec=KEY_SPEC,
            KeyUsage=KEY_USAGE,
            Origin="AWS_KMS",
            Description=(description or f"Tenant key for {tenant_did}")
        )
        key_id = resp["KeyMetadata"]["KeyId"]
        logging.info("Created key id: %s", key_id)

        # Immediately lock the policy down (drop PutKeyPolicy from the app role)
        final_policy = build_final_policy(app_role_arn=app_arn, account_id=account_id, admin_role_arn=KMS_ADMIN_ROLE_ARN)
        self.kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(final_policy))

        # create alias
        try:
            self.kms.create_alias(AliasName=alias_name, TargetKeyId=key_id)
            logging.info("Created alias: %s", alias_name)
        except ClientError as e:
            # if alias already exists (race), fetch the alias target
            logging.warning("create_alias error: %s", str(e))
            existing_alias = self.alias_exists(alias_name)
            if existing_alias and existing_alias.get("TargetKeyId"):
                return existing_alias["TargetKeyId"]
            else:
                raise

        # tag the key with the tenant DID for discoverability
        safe_tag = sanitize_tag_value(tenant_did)
        try:
            self.kms.tag_resource(
                KeyId=key_id,
                Tags=[{"TagKey": "tenant_did", "TagValue": safe_tag}]
            )
        except Exception as e:
            logging.warning("Warning: failed tagging key: %s", str(e))

        # KMS may take a second to become fully available via get_public_key
        time.sleep(0.5)
        return key_id

    def get_public_key_pem(self, key_id):
        resp = self.kms.get_public_key(KeyId=key_id)
        der = resp["PublicKey"]
        pubkey = load_der_public_key(der)
        pem = pubkey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        return pem.decode(), pubkey

    def get_public_key_jwk(self, key_id):
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

        # RFC 7638 JWK thumbprint as kid
        thumb_input = json.dumps(
            {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
            separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        kid = b64url(hashlib.sha256(thumb_input).digest())

        return jwk, kid, alg
    
    def sign_message(self, key_id, message_bytes):
        # MessageType=RAW instructs KMS to hash using the signing algorithm's hash (SHA-256 for ECDSA_SHA_256)
        resp = self.kms.sign(
            KeyId=key_id,
            Message=message_bytes,
            MessageType="RAW",
            SigningAlgorithm="ECDSA_SHA_256"
        )
        signature = resp["Signature"]
        # decode ASN.1 DER ECDSA signature into (r,s)
        r, s = decode_dss_signature(signature)
        return signature, (r, s)

    def sign_jwt_with_key(self, key_id, header: dict, payload: dict) -> str:
        # Choose alg from the KMS key spec
        md = self.kms.describe_key(KeyId=key_id)["KeyMetadata"]
        key_spec = md["KeySpec"]
        alg, _crv = _spec_to_alg_and_crv(key_spec)

        # Ensure 'alg' in header; add kid from JWK thumbprint unless caller set one
        jwk, kid, alg_from_key = self.get_public_key_jwk(key_id)
        if "alg" not in header:
            header["alg"] = alg_from_key  # ES256 or ES256K
        if "kid" not in header:
            header["kid"] = kid
        header.setdefault("typ", "JWT")

        # Encode header & payload (base64url, no padding)
        encoded_header = b64url_json(header)
        encoded_payload = b64url_json(payload)
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")

        # Sign with KMS (SHA-256 over signing_input)
        der_sig, (r, s) = self.sign_message(key_id, signing_input)

        # Convert ASN.1/DER ECDSA sig -> JOSE raw (r||s), each 32 bytes, then base64url
        r_bytes = r.to_bytes(32, "big")
        s_bytes = s.to_bytes(32, "big")
        jose_sig = b64url(r_bytes + s_bytes)

        return f"{encoded_header}.{encoded_payload}.{jose_sig}"

    # === convenience: sign JWT for a tenant DID (by alias) ===
    def sign_jwt_for_tenant(self, tenant_did: str, header: dict, payload: dict) -> str:
        alias_name = sanitize_alias_from_did(tenant_did)
        # resolve alias -> key id
        md = self.kms.describe_key(KeyId=alias_name)
        key_id = md["KeyMetadata"]["KeyId"]
        return self.sign_jwt_with_key(key_id, header, payload)


    def verify_tenant_jwt_with_jwcrypto(self, tenant_did: str, jwt_compact: str):
        """
        Convenience: resolve tenant alias -> key -> JWK, then verify the JWT with jwcrypto.
        """
        alias = sanitize_alias_from_did(tenant_did)
        md = self.kms.describe_key(KeyId=alias)
        key_id = md["KeyMetadata"]["KeyId"]
        jwk, kid, alg = self.get_public_key_jwk(key_id)
        return verify_jwt_with_jwcrypto(jwt_compact, jwk)


    # --- JWS verification with jwcrypto ---
def verify_jwt_with_jwcrypto(jwt_compact: str, jwk_dict: dict):
    """
    Verifies a compact JWS/JWT using jwcrypto and the given public JWK.
    Returns (header_dict, payload_dict) on success; raises on failure.

    Note: jwcrypto supports ES256 (P-256). ES256K (secp256k1) requires jwcrypto/cryptography
    versions that include secp256k1; if not available, you'll get NotImplementedError.
    """

    key = _jwk.JWK.from_json(_json.dumps(jwk_dict))
    token = _jws.JWS()
    token.deserialize(jwt_compact)

    # Let jwcrypto select the algorithm from the header (alg)
    try:
        token.verify(key)
    except NotImplementedError as e:
        raise RuntimeError(
            "Your jwcrypto/cryptography build doesn't support the JWT alg in the header "
            "(likely ES256K). Upgrade jwcrypto & cryptography, or verify via cryptography manually."
        ) from e

    # Extract JOSE header + payload as dicts
    header = _json.loads(token.jose_header) if isinstance(token.jose_header, str) else token.jose_header
    payload = _json.loads(token.payload.decode("utf-8"))
    return header, payload
    
    
# === demo flow ===
def test_flow(tenant_did: str):
    manager = TenantKMSManager()
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
    # quick demo
    demo_did = "did:web:wallet4agent.com:demo#key-1"
    test_flow(demo_did)
