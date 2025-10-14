import os
import base64
import hashlib
import hmac
import json
import time
import uuid
import requests
from typing import Optional

class TrustedAppSigner:
    def __init__(self, account: dict):
        with open('QTSP/vintegris/vintegris.json') as f:
                vintegris = json.load(f)
        # Load configuration from environment or secure storage
        self.api_csc = vintegris["api_csc"]
        self.api = vintegris["api"]
        
        self.username = account["username"]
        self.password = account["password"]
        self.ta_access_identifier = account["access_identifier"]
        self.ta_access_key = account["access_key"]
        self.tenant_id = account["tenant_id"]
        self.app_name = account["app_name"]
        
        self.tuid = os.getenv("TUID")
        self.credential_id = None

        self.second_token: Optional[str] = None
        self.app_token: Optional[str] = None
        self.sad: Optional[str] = None

    # === Utility functions ===
    
    def select_credential(self, credential_id: str):
        if credential_id not in self.get_list():
            raise ValueError("This credential does not exist")
        self.credential_id = credential_id

    def b64(self, data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    def b64url(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def sign_hs256(self, key_bytes: bytes, msg: bytes) -> bytes:
        return hmac.new(key_bytes, msg, hashlib.sha256).digest()

    def check_exp(self, token):
        if not token:
            return False
        try:
            payload = token.split('.')[1] + "=" * ((4 - len(token.split('.')[1]) % 4) % 4)
            json_payload = json.loads(base64.urlsafe_b64decode(payload).decode())
            return json_payload['exp'] > int(time.time())
        except Exception:
            return False

    # === Core logic ===

    def build_ta_auth_jwt(self) -> str:
        header = {"typ": "JWT", "alg": "HS256"}
        now = int(time.time())
        payload = {
            "sub": self.tenant_id,
            "iss": self.app_name,
            "azp": self.ta_access_identifier,
            "iat": now,
            "jti": str(uuid.uuid4())
        }
        signing_input = f"{self.b64url(json.dumps(header).encode())}.{self.b64url(json.dumps(payload).encode())}".encode()
        key_bytes = hashlib.sha256(self.ta_access_key.encode()).digest()
        signature = self.sign_hs256(key_bytes, signing_input)
        return f"{signing_input.decode()}.{self.b64url(signature)}"

    def authorize_trusted_app(self, ta_auth_jwt: str) -> str:
        url = f"{self.api}/trustedapps/v1/trusted/app/authorize"
        headers = {"Accept": "application/json", "Authorization": f"Bearer {ta_auth_jwt}"}
        r = requests.post(url, headers=headers)
        r.raise_for_status()
        return r.json()["content"]["authorization"]

    def login_first(self, app_token):
        url = f"{self.api}/trustedapps/v1/trusted/app/login/first?username=" + base64.b64encode("manager".encode()).decode()
        headers = {"Accept": "application/json", "application": app_token}
        r = requests.post(url, headers=headers)
        r.raise_for_status()
        return r.json()["content"]["token"].split()[1]

    def login_second(self, app_token, simple_token):
        url = f"{self.api}/trustedapps/v1/trusted/app/login/second"
        headers = {
            "Accept": "application/json",
            "application": app_token,
            "Authorization": simple_token
        }
        r = requests.post(url, headers=headers)
        r.raise_for_status()
        return r.json()["content"]["token"].split()[1]

    def get_sad(self):
        if not self.credential_id:
            raise ValueError("Credential ID has not been set")
            
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.second_token}",
        }
        body = {"credentialID": self.credential_id, "numSignatures": 1}
        r = requests.post(f"{self.api_csc}/csc/v1/credentials/authorize", json=body, headers=headers)
        r.raise_for_status()
        return r.json()["SAD"]

    
    def get_info(self, credential_id: str):
        if not self.check_exp(self.second_token):
            ta_jwt = self.build_ta_auth_jwt()
            if not self.check_exp(self.app_token):
                self.app_token = self.authorize_trusted_app(ta_jwt)
            simple_token = self.login_first(self.app_token)
            self.second_token = self.login_second(self.app_token, simple_token)
        
        if credential_id not in self.get_list():
            raise ValueError("This credential does not exist")
        
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.second_token}"
        }
        authorize_body = {
            "credentialID": credential_id,
        }
        r = requests.post(f"{self.api_csc}/csc/v1/credentials/info", json=authorize_body, headers=headers)
        print("\nINFO:", r.status_code)
        r.raise_for_status()
        return r.json()
    
    
    def get_list(self):
        if not self.check_exp(self.second_token):
            ta_jwt = self.build_ta_auth_jwt()
            if not self.check_exp(self.app_token):
                self.app_token = self.authorize_trusted_app(ta_jwt)
            simple_token = self.login_first(self.app_token)
            self.second_token = self.login_second(self.app_token, simple_token)
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.second_token}"
        }
        authorize_body = {
            "userID": None,
            "maxResults": 10,
            "pageToken": "MA==",
        }
        r = requests.post(f"{self.api_csc}/csc/v1/credentials/list", json=authorize_body, headers=headers)
        print("\nINFO:", r.status_code, r.text)
        r.raise_for_status()
        return r.json()["credentialIDs"]
        
    
    def sign_hash(self, to_sign: bytes):
        if not self.check_exp(self.second_token):
            ta_jwt = self.build_ta_auth_jwt()
            if not self.check_exp(self.app_token):
                self.app_token = self.authorize_trusted_app(ta_jwt)
            simple_token = self.login_first(self.app_token)
            self.second_token = self.login_second(self.app_token, simple_token)

        if not self.check_exp(self.sad):
            self.sad = self.get_sad()

        doc_hash_b64 = self.b64(hashlib.sha256(to_sign).digest())
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.second_token}",
        }
        body = {
            "credentialID": self.credential_id,
            "SAD": self.sad,
            "hash": [doc_hash_b64],
            "hashAlgo": "2.16.840.1.101.3.4.2.1",
            "signAlgo": "1.2.840.113549.1.1.1"
        }
        r = requests.post(f"{self.api_csc}/csc/v1/signatures/signHash", json=body, headers=headers)
        r.raise_for_status()
        return r.json()["signatures"][0]

