import io
import json
import base64
from typing import Any, Dict, List, Optional
import logging
import requests
import qrcode
from jwcrypto import jwk
from db_model import Wallet, db
import secrets


def _ok_content(blocks: List[Dict[str, Any]], structured: Optional[Dict[str, Any]] = None, is_error: bool = False) -> Dict[str, Any]:
    out: Dict[str, Any] = {"content": blocks}
    if structured is not None:
        out["structuredContent"] = structured
    if is_error:
        out["isError"] = True
    return out


def call_open_wallet(arguments: Dict[str, Any], config: dict) -> Dict[str, Any]:
    wallet_did = arguments.get("wallet_did")
    agent_card_url = arguments.get("agentcard_url")
    did_method = arguments.get("did_method", "did:web")
    if not wallet_did:
        # Generate EC private key (P-256)
        ec_key = jwk.JWK.generate(kty='EC', crv='P-256')
        # JWK exports
        private_jwk_json = ec_key.export(private_key=True)
        public_jwk_json = json.loads(ec_key.export(private_key=False))
        optional_path = secrets.token_hex(16)
        if did_method == "did:web":
            agent_did = "did:web:wallet4agent.com:" + optional_path 
        else:
            jwk_json = json.dumps(public_jwk_json, separators=(",", ":"), sort_keys=True)
            encoded_jwk = base64.urlsafe_b64encode(jwk_json.encode("utf-8")).rstrip(b"=").decode("utf-8")
            agent_did = "did:jwk:" + encoded_jwk
        
        # add alg for DID Document only
        public_jwk_json["alg"] = "ES256"
        did_document = create_did_document(agent_did, public_jwk_json, agent_card_url=agent_card_url)
        this_wallet = Wallet(
            user_id=1,
            optional_path=optional_path,
            did=agent_did,
            did_document=json.dumps(did_document)
        )
        db.session.add(this_wallet)
        db.session.commit()
        text = "New wallet created."
    else: 
        text = "Wallet is now open."
    structured = {"decentralized_identifier": agent_did}
    return _ok_content([{"type": "text", "text": text}], structured=structured)


def create_did_document(did, jwk, agent_card_url=False):
    document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            {
                "@id": "https://w3id.org/security#publicKeyJwk",
                "@type": "@json"
            }
        ],
        "id": did,
        "verificationMethod": [ 
            {
                "id": did + "#key-1",
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": jwk
            }
        ],
        "authentication" : [
            did + "#key-1"
        ],
        "assertionMethod" : [
            did + "#key-1"
        ],
        "keyAgreement" : [
            did + "#key-1"
        ],
        "capabilityInvocation":[
            did + "#key-1"
        ]
    }
    if agent_card_url:
        document["service"] = []
        document["service"].append(
            {
                "id": "#a2a",
                "type": "A2AService",
                "serviceEndpoint": agent_card_url
            }
        )
    return document