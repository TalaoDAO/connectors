import json
from db_model import Wallet, db, Attestation
import secrets
import logging
from utils import oidc4vc
import hashlib
from datetime import datetime
import base64


def store_and_publish(cred, agent_identifier, manager, mode, published=False, type=None):
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
        result = publish(service_id, cred, mode.server, manager)
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


# helper: base64url without padding
def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def publish(service_id, attestation, server, manager):
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

    sd_jwt_presentation = attestation.strip()
    if not sd_jwt_presentation.endswith("~"):
        sd_jwt_presentation = sd_jwt_presentation + "~"

    sd_jwt_plus_kb = sign_and_add_kb(sd_jwt_presentation, wallet_did, manager)
    if not sd_jwt_plus_kb:
        return None

    vp_resource = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation", "EnvelopedVerifiablePresentation"],
        "id": "data:application/dc+sd-jwt," + sd_jwt_plus_kb,
    }

    # Update linked_vp JSON: single entry for key "OASF"
    try:
        linked_vp_json = json.loads(this_wallet.linked_vp or "{}")
    except Exception:
        linked_vp_json = {}
    linked_vp_json[id] = vp_resource
    this_wallet.linked_vp = json.dumps(linked_vp_json)

    # Update DID Document service entries:
    # remove any existing LinkedVerifiablePresentation for this id / OASF
    service_array = did_document.get("service", []) or []
    endpoint = server + "service/" + wallet_did + "/" + id

    new_services = []
    for s in service_array:
        # Keep all services except:
        #  - exact same id, or
        #  - LinkedVerifiablePresentation with same endpoint
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
    logging.info("attestation is published")

    return {
        "service_id": service_id,
        "service": new_service,
        "verifiable_presentation": vp_resource,
    }

    
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
    
