import requests
from jwcrypto import jwk, jwt
import base58  # type: ignore
import json
from datetime import datetime, timezone
import logging
import hashlib
import copy
import base64
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, padding
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import uuid


RESOLVER_LIST = [
    'https://unires:test@unires.talao.co/1.0/identifiers/',
    'https://dev.uniresolver.io/1.0/identifiers/',
    'https://resolver.cheqd.net/1.0/identifiers/'
]

def generate_key(curve):
    """
alg value https://www.rfc-editor.org/rfc/rfc7518#page-6

+--------------+-------------------------------+--------------------+
| "alg" Param  | Digital Signature or MAC      | Implementation     |
| Value        | Algorithm                     | Requirements       |
+--------------+-------------------------------+--------------------+
| RS256        | RSASSA-PKCS1-v1_5 using       | Recommended        |
|              | SHA-256                       |                    |
| RS384        | RSASSA-PKCS1-v1_5 using       | Optional           |
|              | SHA-384                       |                    |
| RS512        | RSASSA-PKCS1-v1_5 using       | Optional           |
|              | SHA-512                       |                    |
| ES256        | ECDSA using P-256 and SHA-256 | Recommended+       |
| ES384        | ECDSA using P-384 and SHA-384 | Optional           |
| ES512        | ECDSA using P-521 and SHA-512 | Optional           |
+--------------+-------------------------------+--------------------+
    """

    if curve in ['P-256', 'P-384', 'P-521', 'secp256k1']:
        key = jwk.JWK.generate(kty='EC', crv=curve)
    elif curve == 'RSA':
        key = jwk.JWK.generate(kty='RSA', size=2048)
    else:
        raise Exception("Curve not supported")
    return json.loads(key.export(private_key=True))



def alg(key) -> str:
    """
    Return the JOSE 'alg' for a given JWK.
    Accepts:
      - dict JWK
      - JSON string containing a JWK
      - jwcrypto.jwk.JWK instance
    """
    # Normalize input type
    if hasattr(key, "export") and callable(getattr(key, "export")):
        # jwcrypto.jwk.JWK -> dict
        key_dict = key.export(as_dict=True)
    elif isinstance(key, str):
        key_dict = json.loads(key)
    elif isinstance(key, dict):
        key_dict = key
    else:
        raise TypeError(f"Unsupported key type: {type(key).__name__}")

    kty = key_dict.get("kty")
    if not kty:
        raise ValueError("Missing 'kty' in JWK")

    if kty == "EC":
        crv = key_dict.get("crv")
        if not crv:
            raise ValueError("Missing 'crv' in EC JWK")

        # Normalize common aliases without mutating input
        crv_norm = {
            "P-256K": "secp256k1",
            "secp256k1": "secp256k1",
            "P-256": "P-256",
            "P-384": "P-384",
            "P-521": "P-521",
        }.get(crv)

        if crv_norm == "secp256k1":
            return "ES256K"
        if crv_norm == "P-256":
            return "ES256"
        if crv_norm == "P-384":
            return "ES384"
        if crv_norm == "P-521":
            return "ES512"

        raise ValueError(f"Unsupported EC curve: {crv}")

    if kty == "RSA":
        return "RS256"

    if kty == "OKP":
        crv = key_dict.get("crv")
        if not crv:
            raise ValueError("Missing 'crv' in OKP JWK")
        if crv == "Ed25519":
            return "EdDSA"
        raise ValueError(f"Unsupported OKP curve for EdDSA: {crv}")

    raise ValueError(f"Unsupported JWK kty: {kty}")


def load_local_key():
    """
    Loads a base64-encoded AES key from keys.json.
    """
    with open("keys.json", "r") as f:
        data = json.load(f)
    key_b64 = data.get("encryption_key")
    if not key_b64:
        raise ValueError("encryption_key not found in keys.json")
    return base64.urlsafe_b64decode(key_b64)


def encrypt_string(plaintext: str) -> str:
    """
    Encrypt a string using AES-GCM and return a base64 ciphertext.
    """
    key = load_local_key()
    aesgcm = AESGCM(key)
    # 96-bit (12-byte) nonce recommended for AES-GCM
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    # Store nonce + ciphertext together (common convention)
    blob = nonce + ciphertext
    return base64.urlsafe_b64encode(blob).decode("ascii")


def decrypt_string(ciphertext_b64: str) -> str:
    """
    Decrypt a base64 ciphertext produced by encrypt_string().
    """
    key = load_local_key()
    aesgcm = AESGCM(key)
    blob = base64.urlsafe_b64decode(ciphertext_b64)
    nonce = blob[:12]
    ciphertext = blob[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def hash_client_secret(text: str) -> str:
    # Basic SHA-256 hash of the client secret (hex)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def generate_access_token(did, role, type, jti=None, duration=None):
    now = int(datetime.timestamp(datetime.now()))
    if not jti:
        jti = secrets.token_hex(16)
    payload = {
        "jti": jti,
        "sub": did,
        "iat": now,
        "type": type,
        "role": role,
    }
    if duration:
        payload["exp"] = now + duration
    if not duration and type == "oauth":
        payload["exp"] = now + 1800
    access_token = encrypt_string(json.dumps(payload))
    return access_token, payload["jti"]

def pub_key(key):
    key = json.loads(key) if isinstance(key, str) else key
    Key = jwk.JWK(**key) 
    return Key.export_public(as_dict=True)

def salt():
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().replace("=", "")

def hash(text):
    m = hashlib.sha256()
    m.update(text.encode())
    return base64.urlsafe_b64encode(m.digest()).decode().replace("=", "")


def sd(data):
    unsecured = copy.deepcopy(data)
    payload = {'_sd': []}
    disclosed_claims = ['status', 'status_list', 'idx', 'uri', 'vct', 'iat', 'nbf', 'aud', 'iss', 'exp', '_sd_alg', 'cnf']
    _disclosure = ""
    disclosure_list = unsecured.get("disclosure", [])
    for claim in [attribute for attribute in unsecured.keys()]:
        if claim == "disclosure":
            pass
        # for undisclosed attribute
        elif isinstance(unsecured[claim], (str, bool, int)) or claim in ["status", "status_list"]:
            if claim in disclosure_list or claim in disclosed_claims:
                payload[claim] = unsecured[claim]
            else:
                contents = json.dumps([salt(), claim, unsecured[claim]])
                disclosure = base64.urlsafe_b64encode(contents.encode()).decode().replace("=", "")
                if disclosure:
                    _disclosure += "~" + disclosure
                payload['_sd'].append(hash(disclosure))
        # for nested json
        elif isinstance(unsecured[claim], dict):
            if claim in disclosure_list or claim in disclosed_claims:
                payload[claim], disclosure = sd(unsecured[claim])
                if disclosure:
                    _disclosure += "~" + disclosure
            else:
                nested_content, nested_disclosure = sd(unsecured[claim])
                contents = json.dumps([salt(), claim, nested_content])
                if nested_disclosure:
                    _disclosure += "~" + nested_disclosure
                disclosure = base64.urlsafe_b64encode(contents.encode()).decode().replace("=", "")
                if disclosure:
                    _disclosure += "~" + disclosure
                payload['_sd'].append(hash(disclosure))
        # for list
        elif isinstance(unsecured[claim], list):  # list
            if claim in disclosure_list or claim in disclosed_claims:
                payload[claim] = unsecured[claim]
            else:
                nb = len(unsecured[claim])
                payload.update({claim: []})
                for index in range(0, nb):
                    if isinstance(unsecured[claim][index], dict):
                        nested_disclosure_list = unsecured[claim][index].get("disclosure", [])
                        if not nested_disclosure_list:
                            logging.warning("disclosure is missing for %s", claim)
                    else:
                        nested_disclosure_list = []
                for index in range(0, nb):
                    if isinstance(unsecured[claim][index], dict):
                        pass  # TODO
                    elif unsecured[claim][index] in nested_disclosure_list:
                        payload[claim].append(unsecured[claim][index])
                    else:
                        contents = json.dumps([salt(), unsecured[claim][index]])
                        nested_disclosure = base64.urlsafe_b64encode(contents.encode()).decode().replace("=", "")
                        if nested_disclosure:
                            _disclosure += "~" + nested_disclosure
                        payload[claim].append({"...": hash(nested_disclosure)})
        else:
            logging.warning("type not supported")
    if payload.get('_sd'):
        # add 1 fake digest
        contents = json.dumps([salt(), "decoy", "decoy"])
        disclosure = base64.urlsafe_b64encode(contents.encode()).decode().replace("=", "")
        payload['_sd'].append(hash(disclosure))
    else:
        payload.pop("_sd", None)
    _disclosure = _disclosure.replace("~~", "~")
    return payload, _disclosure


def sign_sdjwt_by_agent(unsecured, agent_identifier, target_agent, manager, draft=13, duration=360*24*60*60):
    # bypass selective disclosure if needed
    if "all" in unsecured.get("disclosure", []):
        payload, _disclosure = unsecured, ""
        payload.pop("disclosure")
    else:
        payload, _disclosure = sd(unsecured)
        
    # lazily create or fetch tenant key
    key_id = manager.create_or_get_key_for_tenant(agent_identifier)
    jwk, kid, alg = manager.get_public_key_jwk(key_id)
    
    header = {
        "alg": alg,
        "kid": agent_identifier + "#key-1",
        'typ': "dc+sd-jwt" if draft >= 15 else "vc+sd-jwt"
    }
    
    payload_update = {
        'jti':  str(uuid.uuid4()),
        'aud': target_agent,
        'iss': agent_identifier,
        'iat': int(datetime.timestamp(datetime.now())),
        "_sd_alg": "sha-256",
        "cnf":  {"kid": target_agent + "#key-1"}
    }
    payload.update(payload_update)
    
    # update expiration date with duration if not done before
    if not payload.get("exp"):
        payload["exp"] = int(datetime.timestamp(datetime.now())) + duration,

    # clean
    if not payload.get("_sd"):
        payload.pop("_sd_alg", None)
    
    sd_token = manager.sign_jwt_with_key(key_id, header, payload)
    sd_token += _disclosure + "~"
    return sd_token


def public_key_multibase_to_jwk(mb):
    decoded = _multibase_base58btc_decode(mb)
    multicodec_value, off = _varint_decode(decoded, 0)
    raw = decoded[off:]
    jwk: Dict[str, Any]

    # Standard did:key types
    if multicodec_value == 0xED:  # ed25519-pub
        if len(raw) != 32:
            raise ValueError(f"invalidPublicKeyLength: Ed25519 expected 32, got {len(raw)}")
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}

    elif multicodec_value == 0x1200:  # p256-pub (compressed point, 33 bytes)
        if len(raw) != 33:
            raise ValueError(f"invalidPublicKeyLength: P-256 expected 33, got {len(raw)}")
        jwk = _ec_point_to_jwk("P-256", raw)

    elif multicodec_value == 0xE7:  # secp256k1-pub (compressed point, 33 bytes)
        if len(raw) != 33:
            raise ValueError(f"invalidPublicKeyLength: secp256k1 expected 33, got {len(raw)}")
        jwk = _ec_point_to_jwk("secp256k1", raw)

    # EBSI Natural Person did:key profile:
    # multicodec public-key-type "jwk_jcs-pub" (0xEB51), raw bytes are a JCS-canonicalized public JWK JSON
    elif multicodec_value == 0xEB51:
        try:
            jwk_json = raw.decode("utf-8")
            parsed = json.loads(jwk_json)
        except Exception as e:
            raise ValueError("Invalid jwk_jcs-pub payload (expected UTF-8 JSON JWK).") from e

        jwk = _validate_supported_jwk(parsed)

    else:
        raise ValueError(f"Unsupported multicodec: 0x{multicodec_value:x}")
    return jwk



def base58_to_jwk(base58_key: str):
    key_bytes = base58.b58decode(base58_key)
    x_b64url = base64.urlsafe_b64encode(key_bytes).decode().rstrip("=")
    jwk = {
        "kty": "OKP",  # Type de clé pour Ed25519
        "crv": "Ed25519",
        "x": x_b64url
    }
    return jwk


def base58_to_jwk_secp256k1(base58_key: str):
    key_bytes = base58.b58decode(base58_key)
    if len(key_bytes) == 33 and key_bytes[0] in (2, 3):  # Format compressé
        raise ValueError("Format compressé non supporté directement, il faut le décompresser.")
    elif len(key_bytes) == 65 and key_bytes[0] == 4:  # Format non compressé
        x_bytes = key_bytes[1:33]
        y_bytes = key_bytes[33:65]
    else:
        raise ValueError("Format de clé non reconnu.")
    x_b64url = base64.urlsafe_b64encode(x_bytes).decode().rstrip("=")
    y_b64url = base64.urlsafe_b64encode(y_bytes).decode().rstrip("=")
    jwk = {
        "kty": "EC",
        "crv": "secp256k1",
        "x": x_b64url,
        "y": y_b64url
    }
    return jwk




def _multibase_base58btc_decode(mb: str) -> bytes:
    # did:key uses multibase; base58btc is indicated by leading "z"
    if not mb or mb[0] != "z":
        raise ValueError("Unsupported multibase (expected base58btc starting with 'z').")
    return base58.b58decode(mb[1:])


def _varint_decode(buf: bytes, offset: int = 0):
    """
    Unsigned varint decode (multicodec prefixes are varints).
    Returns (value, new_offset).
    """
    value = 0
    shift = 0
    i = offset
    while True:
        if i >= len(buf):
            raise ValueError("Truncated varint")
        b = buf[i]
        i += 1
        value |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return value, i
        shift += 7
        if shift > 63:
            raise ValueError("Varint too long")


def _ec_point_to_jwk(curve: str, pub_bytes: bytes):
    """
    pub_bytes is a SEC1-encoded point (did:key spec uses compressed points for p256/secp256k1).
    """
    if curve == "P-256":
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)
        size = 32
    elif curve == "secp256k1":
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub_bytes)
        size = 32
    else:
        raise ValueError(f"Unsupported EC curve: {curve}")

    nums = pub.public_numbers()
    return {
        "kty": "EC",
        "crv": curve,
        "x": _b64url(nums.x.to_bytes(size, "big")),
        "y": _b64url(nums.y.to_bytes(size, "big")),
    }


def _validate_supported_jwk(jwk):
    """
    Enforce: only Ed25519, P-256, secp256k1 public keys.
    """
    if not isinstance(jwk, dict):
        raise ValueError("Invalid JWK: not an object")

    kty = jwk.get("kty")
    crv = jwk.get("crv")

    if kty == "OKP":
        if crv != "Ed25519":
            raise ValueError(f"Unsupported OKP curve: {crv}")
        if "x" not in jwk:
            raise ValueError("Invalid Ed25519 JWK: missing 'x'")
        return {"kty": "OKP", "crv": "Ed25519", "x": jwk["x"]}

    if kty == "EC":
        if crv not in ("P-256", "secp256k1"):
            raise ValueError(f"Unsupported EC curve: {crv}")
        if "x" not in jwk or "y" not in jwk:
            raise ValueError("Invalid EC JWK: missing 'x'/'y'")
        return {"kty": "EC", "crv": crv, "x": jwk["x"], "y": jwk["y"]}

    raise ValueError(f"Unsupported JWK kty: {kty}")


def resolve_did_key(did_or_kid: str):
    """
    Resolve did:key locally for:
        - Ed25519 (multicodec 0xED)
        - P-256   (multicodec 0x1200)
        - secp256k1 (multicodec 0xE7)
        - EBSI did:key profile: jwk_jcs-pub (multicodec 0xEB51)
    """
    if not did_or_kid.startswith("did:key:"):
        raise ValueError("Not a did:key identifier")

    did = did_or_kid.split("#", 1)[0]
    mb = did[len("did:key:") :]
    return public_key_multibase_to_jwk(mb)


def resolve_did(vm) -> dict:
    """Return public key in jwk format from Verification Method"""
    logging.info('vm = %s', vm)
    jwk = None
    did_document = None
    try:
        if not vm.startswith("did:"):
            logging.error("Not a verificationMethod  %s", vm)
            return
        did = vm.split('#')[0]
    except Exception as e:
        logging.error("This verification method is not supported  %s", vm + " " + str(e))
        return 
    if did.startswith("did:key"):
        return resolve_did_key(vm)
    
    elif did.startswith("did:jwk"):
        key = did.split(':')[2]
        key += "=" * ((4 - len(key) % 4) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(key))
        except Exception:
            logging.warning("did:jwk is not formated correctly")
            return
    else:
        for res in RESOLVER_LIST:
            url = res + did
            try:
                r = requests.get(url, timeout=10)
                if not r.ok:
                    continue
                body = r.json()
            except Exception:
                continue
            did_document = body.get("didDocument")
            if not did_document:
                logging.warning("DID Document not found for resolver = %s", res)
            else:
                break
    if not did_document:
        logging.warning("DID Document not found")
        return
    logging.info("resolver used = %s", res)
    try:
        vm_list = did_document['verificationMethod']
    except Exception:
        logging.warning("No DID Document or verification method")
        return
    for verificationMethod in vm_list:
        if verificationMethod['id'] == vm: # or (('#' + vm.split('#')[1]) == verificationMethod['id']) :
            if verificationMethod.get('publicKeyJwk'):
                jwk = verificationMethod['publicKeyJwk']
                break
            elif verificationMethod.get('publicKeyBase58'):
                if verificationMethod["type"] in ["Ed25519VerificationKey2020","Ed25519VerificationKey2018"]:
                    jwk = base58_to_jwk(verificationMethod['publicKeyBase58'])
                    break
                else:
                    jwk = base58_to_jwk_secp256k1(verificationMethod['publicKeyBase58'])
                    break
            elif verificationMethod.get("publicKeyMultibase"):
                jwk = public_key_multibase_to_jwk(verificationMethod["publicKeyMultibase"])
                break
            else:
                logging.warning("Unsupported verification method.")
                return
    return jwk


def verif_token(token: str):
    header = get_header_from_token(token)
    if x5c_list := header.get('x5c'):
        try:
            cert_der = base64.b64decode(x5c_list[0])
            cert = x509.load_der_x509_certificate(cert_der)
            public_key = cert.public_key()
            issuer_key = jwk.JWK.from_pyca(public_key)
        except Exception as e:
            raise ValueError(f"Invalid x5c certificate or public key extraction failed: {e}")

    elif header.get('jwk'):
        try:
            jwk_data = header['jwk']
            if isinstance(jwk_data, str):
                jwk_data = json.loads(jwk_data)
            issuer_key = jwk.JWK(**jwk_data)
        except Exception as e:
            raise ValueError(f"Invalid 'jwk' in header: {e}")

    elif header.get('kid'):
        dict_key = resolve_did(header['kid'])
        if not dict_key or not isinstance(dict_key, dict):
            raise ValueError(f"Unable to resolve public key from kid: {header['kid']}")
        try:
            issuer_key = jwk.JWK(**dict_key)
        except Exception as e:
            raise ValueError(f"Invalid public key structure from DID: {e}")

    else:
        raise ValueError("Header missing key info: expected 'x5c', 'jwk', or 'kid'")

    try:
        parsed_jwt = jwt.JWT.from_jose_token(token)
        parsed_jwt.validate(issuer_key)
    except Exception as e:
        raise ValueError(f"JWT signature validation failed: {e}")

    return True  # if no exceptions, verification succeeded


def get_payload_from_token(token) -> dict:
    if not token:
        return {}
    payload = token.split('.')[1]
    payload += "=" * ((4 - len(payload) % 4) % 4)  # solve the padding issue of the base64 python lib
    try:
        payload_as_dict = json.loads(base64.urlsafe_b64decode(payload).decode())
        return payload_as_dict
    except Exception as e:
        raise ValueError(f"Invalid token payload: {e}")


def get_header_from_token(token):
    if not token:
        return {}
    header = token.split('.')[0]
    header += "=" * ((4 - len(header) % 4) % 4)  # solve the padding issue of the base64 python lib
    try:
        return json.loads(base64.urlsafe_b64decode(header).decode())
    except Exception as e:
        raise ValueError(f"Invalid token header: {e}")


def base64url_decode(input_str):
    padding = '=' * (4 - (len(input_str) % 4))
    return base64.urlsafe_b64decode(input_str + padding)


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def thumbprint(key):
    key_obj = json.loads(key) if isinstance(key, str) else dict(key)
    if key_obj.get('crv') == 'P-256K':
        key_obj['crv'] = 'secp256k1'
    signer_key = jwk.JWK(**key_obj)
    return signer_key.thumbprint()


def verification_method(did, key):  # = kid
    key = json.loads(key) if isinstance(key, str) else key
    signer_key = jwk.JWK(**key)
    thumb_print = signer_key.thumbprint()
    return did + '#' + thumb_print


def load_cert_from_b64(b64_der):
    der = base64.b64decode(b64_der)
    return x509.load_der_x509_certificate(der)


def verify_signature(cert, issuer_cert):
    pubkey = issuer_cert.public_key()
    try:
        if isinstance(pubkey, rsa.RSAPublicKey):
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
        elif isinstance(pubkey, ed25519.Ed25519PublicKey):
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes
            )
        else:
            return f"Error: Unsupported public key type: {type(pubkey)}"
        return None  # success
    except InvalidSignature:
        return "Error: Signature verification failed."
    except Exception as e:
        return f"Error: Verification failed with exception: {e}"


def verify_x5c_chain(x5c_list):
    """
    Verifies a certificate chain from the x5c header field of a JWT.
    
    Checks:
      1. Each certificate is signed by the next one in the list.
      2. Each certificate is valid db.Column(db.String(64))at the current time.
    
    Args:
        x5c_list (List[str]): List of base64-encoded DER certificates (leaf to root).
    
    Returns:
        str: Info or error message.
    """
    if not x5c_list or len(x5c_list) < 2:
        return "Error: Insufficient certificate chain."

    try:
        certs = [load_cert_from_b64(b64cert) for b64cert in x5c_list]
    except Exception as e:
        return f"Error loading certificates: {e}"

    now = datetime.now(timezone.utc)

    for i, cert in enumerate(certs):
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            return (
                f"Error: Certificate {i} is not valid at current time:\n"
                f" - Not before: {cert.not_valid_before_utc}\n"
                f" - Not after : {cert.not_valid_after_utc}"
            )
        else:
            logging.info(f"Certificate {i} is within validity period.")

    for i in range(len(certs) - 1):
        cert = certs[i]
        issuer_cert = certs[i + 1]
        result = verify_signature(cert, issuer_cert)
        if result:
            return f"Error: Certificate {i} verification failed: {result}"
        else:
            logging.info(f"Certificate {i} is signed by certificate {i+1}.")

    return "Info: Certificate chain and validity periods are all OK."
