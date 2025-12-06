import json
from db_model import Wallet, db, Attestation
import secrets
import logging
from utils import oidc4vc
import hashlib
from datetime import datetime
import base64
from universal_registrar import UniversalRegistrarClient


# FOR OASF only TODO
def store_and_publish(cred, agent_identifier, manager, mode, published=False, type="OASF"):
    """ The OASF attestation is unique"""
    # store attestation
    vcsd = cred.split("~") 
    vcsd_jwt = vcsd[0]
    try:
        attestation_header = oidc4vc.get_header_from_token(vcsd_jwt)
        attestation_payload = oidc4vc.get_payload_from_token(vcsd_jwt)
    except Exception:
        return None, "Attestation is in an incorrect format and cannot be stored"

    # attestation as a service id
    if type == "OASF":
        id = "OASF"
    else:    
        id = secrets.token_hex(16)
    service_id = agent_identifier + "#" + id
    
    if published:
        result = publish_linked_vp(
            service_id=service_id,
            attestation=cred,
            server=mode.server,
            mode=mode,
            manager=manager,
            vc_format="dc+sd-jwt",
        )
        if not result:
            logging.warning("publish failed")
            published = False
    
    attestation = Attestation.query.filter(Attestation.service_id == service_id).one_or_none()    
    if not attestation:
        attestation = Attestation(
                wallet_did=agent_identifier,
                service_id=service_id,
                vc=cred,
                vc_format=attestation_header.get("typ"),
                issuer=attestation_payload.get("iss"),
                vct=attestation_payload.get("vct"),
                name=attestation_payload.get("name",""),
                description=attestation_payload.get("description",""),
                published=published
            )
        db.session.add(attestation)
        text = "New attestation has been stored"
    else:
        attestation.vc = cred
        attestation.name = attestation_payload.get("name","")
        attestation.description = attestation_payload.get("description","")
        attestation.published = published
        text = "OASF has been updated"
    db.session.commit()
    if attestation: 
        logging.info("credential is stored as attestation #%s", attestation.id)
    return True, text



def publish_linked_vp(service_id: str, attestation: str, server: str, mode, manager, vc_format: str):
    wallet_did = service_id.split("#")[0]
    id = service_id.split("#")[1]

    this_wallet = Wallet.query.filter(Wallet.did == wallet_did).one_or_none()
    if this_wallet is None:
        logging.error("Wallet not found for DID %s", wallet_did)
        return None

    try:
        did_document = json.loads(this_wallet.did_document or "{}")
    except Exception:
        logging.exception("Invalid DID Document in wallet")
        return None

    # ---- SD-JWT formats ----
    if vc_format in ["vc+sd-jwt", "dc+sd-jwt"]:
        sd_jwt_presentation = attestation.strip()
        if not sd_jwt_presentation.endswith("~"):
            sd_jwt_presentation = sd_jwt_presentation + "~"

        sd_jwt_plus_kb = sign_and_add_kb(sd_jwt_presentation, wallet_did, manager)
        if not sd_jwt_plus_kb:
            return None

        vp_value = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation", "EnvelopedVerifiablePresentation"],
            "id": "data:application/dc+sd-jwt," + sd_jwt_plus_kb,
        }

    # ---- Other VC formats (jwt_vc_json, ldp_vc, ...) ----
    else:
        payload = {
            "iss": wallet_did,
            "sub": wallet_did,
            "jti": secrets.token_urlsafe(16),
            "iat": int(datetime.utcnow().timestamp()),
            "vp": {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiablePresentation"],
                "holder": wallet_did,
                "verifiableCredential": [attestation],
            },
        }
        vm = wallet_did + "#key-1"
        key_id = manager.create_or_get_key_for_tenant(vm)
        jwk, kid, alg = manager.get_public_key_jwk(key_id)
        header = {
            "kid": vm,
            "alg": alg,
            "typ": "JWT",
        }
        vp_jwt = manager.sign_jwt_with_key(key_id, header=header, payload=payload)
        vp_value = vp_jwt

    # ---- Update wallet.linked_vp ----
    try:
        linked_vp_json = json.loads(this_wallet.linked_vp or "{}")
    except Exception:
        linked_vp_json = {}
    linked_vp_json[id] = vp_value
    this_wallet.linked_vp = json.dumps(linked_vp_json)

    # ---- Update DID Document service entries (this is where #OASF uniqueness happens) ----
    service_array = did_document.get("service", []) or []
    endpoint = server + "service/" + wallet_did + "/" + id

    new_services = []
    for s in service_array:
        if s.get("id") == service_id:
            continue
        if s.get("type") == "LinkedVerifiablePresentation" and s.get("serviceEndpoint") == endpoint:
            continue
        new_services.append(s)

    new_service = {
        "id": service_id,
        "type": "LinkedVerifiablePresentation",
        "serviceEndpoint": endpoint,
    }
    new_services.append(new_service)

    did_document["service"] = new_services
    this_wallet.did_document = json.dumps(did_document)
    db.session.commit()
    
    # After local update, if this is a did:cheqd, also update on-ledger via Universal Registrar
    if wallet_did.startswith("did:cheqd:"):
        registrar = UniversalRegistrarClient()
        # extract network from did:cheqd:<network>:<id>
        parts = wallet_did.split(":")
        network = parts[2] if len(parts) > 3 else "testnet"
            
        vm_id = wallet_did + "#key-1"
        auth = did_document.get("authentication", [])
        if vm_id not in auth:
            auth.append(vm_id)
        did_document["authentication"] = auth
        
        try:
            registrar.update_did_cheqd(
                did=wallet_did,
                did_document=did_document,
                manager=manager,
                mode=mode,
                network=network,
            )
            logging.info("Linked VP published on-ledger for %s", wallet_did)
        except Exception as e:
            logging.error("Failed to update cheqd DID document for %s: %s", wallet_did, str(e))
            return None

    logging.info("Linked VP published for %s (format=%s)", service_id, vc_format)

    return {
        "service_id": service_id,
        "service": new_service,
        "verifiable_presentation": vp_value,
    }


# helper: base64url without padding
def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


    
def sign_and_add_kb(sd_jwt, wallet_did, manager):
    sd_jwt_presentation = sd_jwt.split("~")[0]
    now = int(datetime.utcnow().timestamp())
    nonce = secrets.token_urlsafe(16)
    vm = wallet_did + "#key-1"
    key_id = manager.create_or_get_key_for_tenant(vm)
    jwk, kid, alg = manager.get_public_key_jwk(key_id)

    # sd_hash = b64url( SHA-256( ascii(SD-JWT-presentation) ) )
    digest = hashlib.sha256(sd_jwt_presentation.encode("ascii")).digest()
    sd_hash = base64url_encode(digest)

    header = {
        "typ": "kb+jwt",
        "alg": alg,
    }
    payload = {
        "iat": now,
        "aud": wallet_did,
        "nonce": nonce,
        "sd_hash": sd_hash,
    }
    kb_token = manager.sign_jwt_with_key(key_id, header=header, payload=payload)
    return sd_jwt_presentation + "~" + kb_token  # compact JWS
    
# linked_vp.py

def unpublish_linked_vp(service_id: str, server: str, mode, manager):
    """
    Remove a Linked Verifiable Presentation (Linked VP) from:
      - wallet.linked_vp map
      - DID Document 'service' array

    If the wallet DID is did:cheqd, also push the updated DID Document
    on-ledger via Universal Registrar.

    The underlying Attestation row is NOT deleted; the caller is
    responsible for updating Attestation.published.
    """
    wallet_did = service_id.split("#")[0]
    id = service_id.split("#")[1]

    this_wallet = Wallet.query.filter(Wallet.did == wallet_did).one_or_none()
    if this_wallet is None:
        logging.error("Wallet not found for DID %s", wallet_did)
        return None

    # Load DID Document
    try:
        did_document = json.loads(this_wallet.did_document or "{}")
    except Exception:
        logging.exception("Invalid DID Document in wallet")
        return None

    # ---- Update wallet.linked_vp ----
    try:
        linked_vp_json = json.loads(this_wallet.linked_vp or "{}")
    except Exception:
        linked_vp_json = {}

    if id in linked_vp_json:
        del linked_vp_json[id]
    this_wallet.linked_vp = json.dumps(linked_vp_json)

    # ---- Update DID Document service entries ----
    service_array = did_document.get("service", []) or []
    endpoint = server + "service/" + wallet_did + "/" + id

    new_services = []
    for s in service_array:
        # Remove the exact service_id
        if s.get("id") == service_id:
            continue
        # Also remove any lingering LinkedVerifiablePresentation with same endpoint
        if s.get("type") == "LinkedVerifiablePresentation" and s.get("serviceEndpoint") == endpoint:
            continue
        new_services.append(s)

    did_document["service"] = new_services
    this_wallet.did_document = json.dumps(did_document)
    db.session.commit()

    # ---- If did:cheqd, push update to ledger ----
    if wallet_did.startswith("did:cheqd:"):
        try:
            registrar = UniversalRegistrarClient()
            parts = wallet_did.split(":")
            network = parts[2] if len(parts) > 3 else "testnet"

            registrar.update_did_cheqd(
                did=wallet_did,
                did_document=did_document,
                manager=manager,
                mode=mode,
                network=network,
            )
            logging.info("Linked VP unpublished on-ledger for %s", wallet_did)
        except Exception as e:
            logging.exception("Failed to update cheqd DID document for %s: %s", wallet_did, str(e))
            return None

    logging.info("Linked VP unpublished for %s", service_id)
    return {
        "service_id": service_id,
        "removed": True,
    }
