import base64
import json
import random
import string
import uuid
from typing import Any, Dict, Optional, Tuple
import logging
import requests
from utils.did_document import build_jwk_did_document
from db_model import Wallet
from key_manager import TenantKMSManager  # type: ignore

UNIVERSAL_REGISTRAR_BASE_URL = "http://localhost:9080/1.0"


# -------------------------------------------------------------------
# Helpers for secp256k1 JWK -> uncompressed publicKeyHex (for did:ethr)
# -------------------------------------------------------------------
def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_to_bytes(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def jwk_to_uncompressed_secp256k1_hex(jwk: Dict[str, Any]) -> str:
    if jwk.get("kty") != "EC":
        raise ValueError(f"Expected EC JWK, got kty={jwk.get('kty')}")
    if jwk.get("crv") not in ("secp256k1", "P-256K", "P-256K1"):
        raise ValueError(f"Expected secp256k1 JWK, got crv={jwk.get('crv')}")

    x_bytes = _b64url_to_bytes(jwk["x"])
    y_bytes = _b64url_to_bytes(jwk["y"])

    if len(x_bytes) != 32 or len(y_bytes) != 32:
        raise ValueError("Unexpected coordinate length for secp256k1 (expected 32 bytes each)")

    return "04" + x_bytes.hex() + y_bytes.hex()




class UniversalRegistrarClient:
    """
    Helper around your local Universal Registrar instance.

    - tenant = DID (the identity)
    - key    = verificationMethod (vm.id), mapped to an AWS KMS key

    It knows how to:
    - Create did:web using P-256 keys from AWS KMS
    - Create did:cheqd using Ed25519 from local KMS with 2-step signing
    """

    def __init__(self, base_url: str = UNIVERSAL_REGISTRAR_BASE_URL):
        self.base_url = base_url.rstrip("/")

    def create_did_web(
        self,
        manager,
        wallet_identifier,
        mode,
        agentcard_url,
        name=None,
        controller=None
    ) -> Tuple[str, Dict[str, Any], str]:
        """
        Create a did:web remotely using a P-256 key in KMS.
        tenant = DID
        key = verificationMethod (vm_id = did + "#key-1")
        """
        # Use agent name if provided, or random digits to avoid collisions
        random_numbers = "".join(random.choice(string.digits) for _ in range(9))
        if not name:
            name = random_numbers

        did = f"did:web:wallet4agent.com:{name}"        

        # avoid collision in your Wallet table
        one_wallet = Wallet.query.filter(Wallet.agent_identifier == did).first()
        if one_wallet:
            did = f"{did}-{random_numbers}"

        key_spec = "ECC_NIST_P256"
        vm_id = did + "#key-1"

        # create/fetch key for this verificationMethod
        key_id = manager.create_or_get_key_for_verification_method(vm_id, key_spec)

        # get JWK from KMS
        jwk, kid, alg = manager.get_public_key_jwk(key_id)
        
        if not controller:
            controller = did

        # build DID Document locally (JsonWebKey2020 + OIDC4VP/A2A)
        did_document = build_jwk_did_document(did, jwk, wallet_identifier, controller, mode, agentcard_url)

        # ✅ No call to Universal Registrar here
        return did, did_document, key_id

    # -------------------- did:cheqd --------------------

    def _build_cheqd_did_and_vm(
        self,
        network: str,
    ) -> Tuple[str, str]:
        method_specific_id = str(uuid.uuid4())
        did = f"did:cheqd:{network}:{method_specific_id}"
        vm_id = did + "#key-1"
        return did, vm_id

    def create_only_wallet(self, agent_identifier, manager):
        key_spec = "ED25519"
        vm_id = agent_identifier + "#key-1"
        key_id = manager.create_or_get_key_for_verification_method(vm_id, key_spec)
        if not key_id:
            return False
        return True
        
        
    def create_did_cheqd(
        self,
        manager,
        wallet_identifier,
        mode,
        agentcard_url,
        controller=None,
        network: str = "testnet",
    ) -> Tuple[str, Dict[str, Any], str]:
        """
        Create a did:cheqd via the cheqd DID Registrar driver using Universal Registrar,
        with signatures done by your KMS (client-managed secret mode).

        - tenant = did:cheqd:<network>:<uuid>
        - key    = vm_id = did + "#key-1"
        """
        did, vm_id = self._build_cheqd_did_and_vm(network)
        key_spec = "ED25519"

        # Key = verificationMethod
        key_id = manager.create_or_get_key_for_verification_method(vm_id, key_spec)
        
        # Build DID Document from the KMS key's JWK
        jwk, kid, alg = manager.get_public_key_jwk(key_id)
        
        if not controller:
            controller = did
        
        did_doc = build_jwk_did_document(did, jwk, wallet_identifier, controller, mode, agentcard_url)
        
        # Ensure the key is also an authentication method
        auth = did_doc.get("authentication", [])
        if vm_id not in auth:
            auth.append(vm_id)
        did_doc["authentication"] = auth
        
        # 1st call: ask driver to prepare signPayload
        initial_body = {
            "didDocument": did_doc,
            "options": {
                "network": network,
            },
            "secret": {},
        }

        resp1 = requests.post(
            f"{self.base_url}/create",
            params={"method": "cheqd"},
            json=initial_body,
            timeout=30,
        )
        resp1.raise_for_status()
        data1 = resp1.json()

        did_state1 = data1.get("didState", {})
        
        did_state1 = data1.get("didState", {})
        if did_state1.get("state") != "action":
            raise RuntimeError(f"Expected 'action' state, got: {did_state1}")

        job_id = data1.get("jobId")
        action = did_state1.get("action")
        if action not in ("signPayload", "sign"):
            raise RuntimeError(f"Unexpected action from cheqd driver: {action}")

        # Universal Registrar → map of signingRequest0, signingRequest1, ...
        signing_requests = did_state1.get("signingRequest") or {}
        if not signing_requests:
            raise RuntimeError(f"cheqd driver returned no signingRequest; didState was: {did_state1}")

        signing_responses: Dict[str, Dict[str, str]] = {}

        for label, req in signing_requests.items():
            # cheqd docs/tests call this 'serializedPayload'
            payload_b64 = req.get("payload") or req["serializedPayload"]
            vm_id_req = req.get("verificationMethodId") or req["kid"]

            payload_bytes = base64.b64decode(payload_b64)
            
            signature, _ = manager.sign_message(key_id, payload_bytes)
            # For Ed25519, the signature is already 64
            raw_sig = signature
            sig_b64 = _b64url_nopad(raw_sig)

            # value shape compatible with both UR driver + cheqd registrar
            signing_responses[label] = {
                "verificationMethodId": vm_id_req,
                "kid": vm_id_req,
                "signature": sig_b64,
            }

        final_body = {
            "jobId": job_id,
            "secret": {
                "signingResponse": signing_responses,
            },
        }

        resp2 = requests.post(
            f"{self.base_url}/create",
            params={"method": "cheqd"},
            json=final_body,
            timeout=30,
        )
        resp2.raise_for_status()
        data2 = resp2.json()

        did_state2 = data2.get("didState", {})
        if did_state2.get("state") != "finished":
            raise RuntimeError(f"cheqd DID registration failed: {did_state2}")

        final_did = did_state2["did"]
        did_doc_result = did_state2.get("didDocument", {})
        return final_did, did_doc_result, key_id
    
    def update_did_cheqd(
        self,
        did: str,
        did_document: Dict[str, Any],
        manager: TenantKMSManager,
        mode,  # kept for future use (env), but not passed to sign_message
        network: str = "testnet",
    ) -> Dict[str, Any]:
        """
        Update an existing did:cheqd DID Document via Universal Registrar, with
        signatures done by your KMS (same pattern as create_did_cheqd).

        - did: the full did:cheqd:<network>:<id>
        - did_document: the *new* DID Document you want on-ledger
        """
        logging.info("Updating did:cheqd DID %s on network %s", did, network)

        # 1) Initial UPDATE call → ask driver to prepare signing payloads
        # NOTE: didDocument MUST be a *list* of DidDocument, per the Universal Registrar
        # UpdateRequest model (hence the server log error you saw).
        initial_body: Dict[str, Any] = {
            "did": did,
            "options": {
                "network": network,
            },
            "didDocument": [did_document],
            "secret": {},
        }

        resp = requests.post(
            f"{self.base_url}/update",
            params={"method": "cheqd"},
            json=initial_body,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()

        did_state = data.get("didState", {})
        state = did_state.get("state")
        if state == "finished":
            # Some drivers might do everything in a single step
            logging.info("cheqd DID update finished in a single step.")
            return did_state

        if state != "action":
            raise RuntimeError(f"cheqd DID update unexpected state: {did_state}")

        action = did_state.get("action")
        if action not in ("signPayload", "sign"):
            raise RuntimeError(f"Unexpected action from cheqd driver on update: {action}")

        # 2) Sign all requested payloads with our KMS key
        # For create_did_cheqd the driver returns:
        #   didState.signingRequest = { "label0": { payload, verificationMethodId, ... }, ... }
        # We mirror this for update.
        signing_requests = did_state.get("signingRequest") or {}

        if not signing_requests:
            raise RuntimeError(f"cheqd DID update: missing signingRequest in didState: {did_state}")

        signing_responses: Dict[str, Dict[str, str]] = {}

        # Our KMS key id is the vm id, same as in create_did_cheqd:
        # did:cheqd:<network>:<id>#key-1
        key_id = did + "#key-1"

        for label, req in signing_requests.items():
            payload_b64 = req.get("payload") or req.get("serializedPayload")
            if not payload_b64:
                raise RuntimeError(f"Missing payload for signingRequest {label}: {req}")

            vm_id_req = key_id

            # For cheqd create, we used plain base64 (not urlsafe) from the driver.
            # We keep the same here for consistency.
            payload_bytes = base64.b64decode(payload_b64)

            signature, _ = manager.sign_message(key_id, payload_bytes)
            raw_sig = signature  # Ed25519 = 64 bytes
            sig_b64 = _b64url_nopad(raw_sig)

            signing_responses[label] = {
                "verificationMethodId": vm_id_req,
                "kid": vm_id_req,
                "signature": sig_b64,
            }

        final_body: Dict[str, Any] = {
            "jobId": data.get("jobId"),
            "secret": {
                "signingResponse": signing_responses,
            },
        }

        resp2 = requests.post(
            f"{self.base_url}/update",
            params={"method": "cheqd"},
            json=final_body,
            timeout=30,
        )
        resp2.raise_for_status()
        data2 = resp2.json()

        did_state2 = data2.get("didState", {})
        if did_state2.get("state") != "finished":
            raise RuntimeError(f"cheqd DID update failed: {did_state2}")

        logging.info("cheqd DID update finished for %s", did)
        return did_state2
