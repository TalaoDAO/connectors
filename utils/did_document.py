import json

def build_jwk_did_document(did, jwk, wallet_identifier, controller, mode, agentcard_url):
    vm_id = did + "#key-1"
    vm = {
        "id": vm_id,
        "type": "JsonWebKey2020",
        "controller": did,
        "publicKeyJwk": jwk,
    }

    document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": did,
        "controller": [controller],
        "verificationMethod": [vm],
        "assertionMethod": [vm_id],
        "authentication": [vm_id],
        "service": [
            {
                "id": did + "#oidc4vc-wallet",
                "type": "OIDC4VCWalletService",
                "serviceEndpoint": f"{mode.server}wallets/{wallet_identifier}"
            },
            #{
            #    "id": did + "#oidc4vci-issuer",
            #    "type": "OIDC4VCIIssuerService",
            #    "serviceEndpoint": f"{mode.server}issuer"
            #}
        ]
    }

    if agentcard_url:
        document["service"].append(
            {
                "id": did + "#a2a",
                "type": "A2AService",
                "serviceEndpoint": agentcard_url,
            }
        )

    return document

def create_did_document(agent_identifier, jwk, wallet_identifier, controller, mode, agentcard_url) -> str:
    document = build_jwk_did_document(agent_identifier, jwk, wallet_identifier, controller, mode, agentcard_url)
    return json.dumps(document)
