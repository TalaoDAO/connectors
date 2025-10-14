from flask import jsonify, Response, current_app
from db_model import db, Verifier
import json


def init_app(app):
    app.add_url_rule('/verifier/<verifier_id>/.well-known/did.json', view_func=did_doc, methods=["GET"])


def did_doc(verifier_id):
    mode = current_app.config["MODE"]
    verifier = Verifier.query.get_or_404(verifier_id)

    # Determine the source of DID and key material
    if verifier.signature == "custom_sandbox" and verifier.client_id_scheme == "decentralized_identifier":
        did = verifier.did
        vm_id = verifier.vm
        key_data = json.loads(verifier.request_key)
    elif verifier.signature == "talao_sandbox" and verifier.client_id_scheme == "decentralized_identifier":
        did = mode.talao_verifier.get("did")
        vm_id = mode.talao_verifier.get("vm")
        key_data = mode.talao_verifier.get("authorization_request_key")
    else:
        return jsonify({"error": "DID not found or unsupported signature/client_id_scheme"}), 404

    # Remove private key if present
    key_data = {k: v for k, v in key_data.items() if k != "d"}

    # Compose DID Document
    did_document = {
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
                "id": vm_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": key_data
            }
        ],
        "authentication": [vm_id],
        "assertionMethod": [vm_id],
        "keyAgreement": [vm_id],
        "capabilityInvocation": [vm_id]
    }

    return Response(
        json.dumps(did_document, indent=2),
        headers={
            "Content-Type": "application/did+ld+json",
            "Cache-Control": "no-cache"
        }
    )
