# vintegris_ta.py — CSC + Trusted Application (TA) support
import base64
import hashlib
import hmac
import json
import time
import uuid
import requests

API_CSC = "https://api-ansmt01.nebulaservice.net"
API = "https://api.nebulaservice.net"

# ── your existing user login (kept for now) ───────────────────────────────────
USERNAME = "manager@talao-demo.com"
PASSWORD = "YcSATe73xm3.c4j"
TUID     = "01"

# ── your credential to sign with ─────────────────────────────────────────────
CREDENTIAL_ID = "f82f470153e86dad92e318ac0c32b221"  # adjust if needed

# ── Trusted Application identifiers you gave me ──────────────────────────────
TA_ACCESS_IDENTIFIER = "36762fb5-ed61-41ae-bd1d-330a9a100d30"  # aka appId / azp
TA_ACCESS_KEY        = "cbfc7012A444b6173CA2c994acf1fb4ac295acA18dFF39221Fb905DEAF70D8f1"

# ── These 2 are tenant/app metadata used inside the TA JWT (fill with your values) ──
TENANT_ID   = "7fdb7386-8e98-40b9-b653-ca98a10b0cb9"       # put your company/tenant ID here
APP_NAME    = "CONNECTORS"     # friendly app name shown as 'iss' in the JWT

SAD = None
second_token = None
app_token = None
# ===== helpers =================================================================

def b64(data: bytes) -> str:
    """Standard Base64 with padding."""
    return base64.b64encode(data).decode("ascii")

def b64url(data: bytes) -> str:
    """Base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def sign_hs256(key_bytes: bytes, msg: bytes) -> bytes:
    return hmac.new(key_bytes, msg, hashlib.sha256).digest()



def check_exp(token):
    if not token:
        return False
    payload = token.split('.')[1]
    payload += "=" * ((4 - len(payload) % 4) % 4)
    try:
        json_payload = json.loads(base64.urlsafe_b64decode(payload).decode())
    except Exception as e:
        raise ValueError(f"Invalid token payload: { e}")
    if json_payload['exp'] > int(time.time()):
        return True
    else:
        return False


def get_user_token() -> str:
    r = requests.post(
        f"{API}/signin/auth/login/first",
        json={"username": USERNAME, "password": PASSWORD, "tuid": TUID},
        headers={"accept": "application/json", "Content-Type": "application/json"},
    )
    print("LOGIN:", r.status_code, r.text[:200])
    r.raise_for_status()
    tok = r.json()["content"]["token"]
    return tok.split()[1] if tok.startswith("Bearer ") else tok


# ===== step 1: build a short-lived TA authentication JWT ======================

def build_ta_auth_jwt() -> str:
    """
    Per portal docs: HS256 JWT; key = SHA256(access_key).
    Claims used commonly: sub (tenant), iss (app name), azp (app id), iat, jti.
    """
    header  = {"typ": "JWT", "alg": "HS256"}
    now     = int(time.time())
    payload = {
        "sub": TENANT_ID,                     # tenant/company id
        "iss": APP_NAME,                      # trusted app display name
        "azp": TA_ACCESS_IDENTIFIER,          # app identifier
        "iat": now,
        "jti": str(uuid.uuid4())
    }
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}".encode()
    key_bytes     = hashlib.sha256(TA_ACCESS_KEY.encode()).digest()
    signature     = sign_hs256(key_bytes, signing_input)
    token = f"{signing_input.decode()}.{b64url(signature)}"
    print(token)
    return token


# ===== step 2: exchange TA JWT for an Application Authorization Token =========

def authorize_trusted_app(ta_auth_jwt: str) -> str:
    """
    Calls the portal’s TA authorize endpoint to get an application token (valid up to ~24h).
    Some deployments expect the JWT in the body; others accept it as Bearer. Try body first.
    """
    url = f"{API}/trustedapps/v1/trusted/app/authorize"
    # Variant A: send token in JSON body   
    headers2 = {"Accept": "application/json", "Authorization": f"Bearer {ta_auth_jwt}"}
    r = requests.post(url, headers=headers2)

    print("TA AUTHORIZE:", r.status_code, r.text)
    r.raise_for_status()

    # Common patterns: {"token": "..."} or {"content":{"token":"..."}} — handle both
    try:
        data = r.json()
        return data["content"]["authorization"]
    except Exception:
        pass
        raise RuntimeError("Could not extract TA application token from response")


def login_first(app_token):
    url = f"{API}/trustedapps/v1/trusted/app/login/first?username=" + base64.b64encode("manager".encode()).decode()
    # Variant A: send token in JSON body   
    headers2 = {"Accept": "application/json", "application": app_token}
    r = requests.post(url, headers=headers2)
    print("LOGIN FIRST:", r.status_code, r.text)
    r.raise_for_status()
    try:
        data = r.json()
        return data["content"]["token"].split()[1]
    except Exception:
        pass
        raise RuntimeError("Could not extract first token from response")


def login_second(app_token, simple_token):
    url = f"{API}/trustedapps/v1/trusted/app/login/second"
    # Variant A: send token in JSON body   
    headers2 = {
        "Accept": "application/json",
        "application": app_token,
        "Authorization": simple_token
    }
    r = requests.post(url, headers=headers2)
    print("LOGIN SECOND:", r.status_code, r.text)
    r.raise_for_status()
    try:
        data = r.json()
        return data["content"]["token"].split()[1]
    except Exception:
        pass
        raise RuntimeError("Could not extract second token from response")
    
    
def get_SAD(second_token, credential_id):
    print("calculate SAD")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {second_token}",                # existing user token
    }
    authorize_body = {
        "credentialID": credential_id,
        "numSignatures": 1
        # "PIN": "...",           # should be unnecessary if TA is allowed to bypass
        # "OTP": "...",           # should be unnecessary for M2M
        # "hash": ["...base64..."]  # add if SCAL == "2"
    }
    r = requests.post(f"{API_CSC}/csc/v1/credentials/authorize", json=authorize_body, headers=headers)
    print("\nAUTHORIZE:", r.status_code, r.text[:400])
    r.raise_for_status()
    return r.json()["SAD"]

def get_info(second_token):
    #CSC Info
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {second_token}",                # existing user token
    }
    authorize_body = {
        "credentialID": CREDENTIAL_ID,
    }
    r = requests.post(f"{API_CSC}/csc/v1/credentials/info", json=authorize_body, headers=headers)
    print("\nINFO:", r.status_code, r.text)
    r.raise_for_status()

    
# ===== step 3: use TA token + (for now) the user token to call CSC ============

def sign_hash(to_sign):
    
    global second_token, SAD, app_token
    
    print("SAD = ", SAD)

    if not check_exp(second_token):
        
        # build TA token
        ta_auth_jwt = build_ta_auth_jwt()
        #print(check_exp(ta_auth_jwt))
    
        # Get application token
        if not check_exp(app_token):
            app_token   = authorize_trusted_app(ta_auth_jwt)

        # Login first
        simple_token = login_first(app_token)
    
        # Login second
        second_token = login_second(app_token, simple_token)
    else:
        print("second token valid")
    
    if not check_exp(SAD):
        # CSC AUthorize
        SAD = get_SAD(second_token, CREDENTIAL_ID) 
    else:
        print("SAD valid")
    
    
    # Prepare a demo hash
    doc_hash_b64 = b64(hashlib.sha256(to_sign).digest())
    # Sign (EC P-256 )
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {second_token}",                # existing user token
    }
    sign_body = {
        "credentialID": CREDENTIAL_ID,
        "SAD": SAD,
        "hash": [doc_hash_b64],
        "hashAlgo": "2.16.840.1.101.3.4.2.1",          # SHA-256
        "signAlgo": "1.2.840.113549.1.1.1"  # RSA

    }
    s = requests.post(f"{API_CSC}/csc/v1/signatures/signHash", json=sign_body, headers=headers)
    print("\nSIGN:", s.status_code, s.text[:400])
    s.raise_for_status()

    data = s.json()
    print(data)
    print("Signature (base64):", data["signatures"][0])

if __name__ == "__main__":
    sign_hash(b"hello world")
    sign_hash(b"Bonjour")
