import json
import logging
import uuid
from datetime import datetime, timedelta
from random import randint
from urllib.parse import quote
import pkce
import requests
from flask import (Response, jsonify, request, current_app)
import didkit
from utils import x509_attestation, oidc4vc
from db_model import Wallet

logging.basicConfig(level=logging.INFO)

ACCESS_TOKEN_LIFE = 5*60  # 5 minutes
OFFER_LIFE = 5*60
REFRESH_TOKEN_LIFE = 24*60*60  # 1 day
GRANT_LIFE = 5*60  # 5 minutes
C_NONCE_LIFE = 5*60  # 5 minutes
STATUSLIST_ISSUER_KEY = json.dumps(json.load(open('keys.json', 'r'))['credentials'][0]["key"])


def init_app(app):
    
    # OAuth 2 AS endpoint when issuer for all wallets
    app.add_url_rule('/issuer/.well-known/oauth-authorization-server', view_func=oauth_authorization_server, methods=['GET'])    
    app.add_url_rule('/issuer/token', view_func=issuer_token, methods=['POST'])
    
    # OIDC4VCI Issuer service endpoint for all wallets = RS
    # credential issuer endpoint = /issuer/<wallet_identifier>
    app.add_url_rule('/issuer/.well-known/openid-credential-issuer', view_func=credential_issuer_metadata_endpoint, methods=['GET'])
    app.add_url_rule('/issuer/credential', view_func=issuer_credential, methods=['POST'])
    app.add_url_rule('/issuer/credential_offer_uri/<id>', view_func=issuer_credential_offer_uri, methods=['GET', 'POST'])
    app.add_url_rule('/issuer/nonce', view_func=issuer_nonce, methods=['POST'])
    #app.add_url_rule('/issuer/error_uri', view_func=wallet_error_uri, methods=['GET'])

    # keys for  sd-jwt vc
    app.add_url_rule('/.well-known/jwt-vc-issuer/issuer/<wallet_identifier>', view_func=openid_jwt_vc_issuer_configuration, methods=['GET'])

    return

def manage_error(error, error_description, red, mode, status=400):
    payload = {
        'error': error,
        'error_description': error_description,
    }
    if error == 'invalid_proof':
        payload['c_nonce'] = str(uuid.uuid1())
        payload['c_nonce_expires_in'] = 86400
    
    logging.info('endpoint error response = %s', json.dumps(payload, indent=4))
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return {'response': json.dumps(payload), 'status': status, 'headers': headers}


def build_issuer_metadata(mode) -> dict:
    logging.info('Call credential issuer configuration endpoint')
    metadata = {
        "credential_issuer": f"{mode.server}issuer",
        "credential_endpoint": f"{mode.server}issuer/credential",
        "nonce_endpoint": f"{mode.server}issuer/nonce"
    }
    metadata["credential_configurations_supported"] = {
        "OBO": {
            "format": "dc+sd-jwt",
            "vct": "urn:ai-agent:obo:0001",
            "scope": "OBO_scope",
            "cryptographic_binding_methods_supported": [
                "did:jwk",
                "did:key",
                "did:web",
                "did:cheqd",
                "jwk"
            ],
            "credential_signing_alg_values_supported": [
                "ES256",
                "EdDSA"
            ],
        }
    }
    return metadata


# credential issuer openid configuration endpoint
def credential_issuer_metadata_endpoint():
    logging.info('Call credential issuer configuration endpoint')
    mode = current_app.config["MODE"]
    metadata = build_issuer_metadata(mode)
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(metadata), headers=headers, status=200)

# jwt vc issuer openid configuration
def openid_jwt_vc_issuer_configuration(wallet_identifier) -> str:
    mode = current_app.config["MODE"]
    manager = current_app.config["MANAGER"]
    wallet = Wallet.query.filter(Wallet.wallet_identifier == wallet_identifier).first()
    vm_id = wallet.agent_identifier + "#key-1"
    try:
        key_id = manager.create_or_get_key_for_tenant(vm_id)
        pub_key = manager.get_public_key_jwk(key_id)
    except Exception:
        pass
    pub_key['kid'] = pub_key.get('kid') if pub_key.get('kid') else oidc4vc.thumbprint(pub_key)
    jwks = {'keys': [pub_key]}
    config = {
        'issuer': mode.server.rstrip("/") + '/issuer/' + wallet_identifier,
        'jwks': jwks
    }
    logging.info('jwks for sd-jwt config = %s', config)
    return jsonify(config)


# /.well-known/oauth-authorization-server endpoint
def oauth_authorization_server():
    mode = current_app.config["MODE"]
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    logging.info('Call to oauth-authorization-server endpoint')
    authorization_server_config = json.load(open('authorization_server_config.json'))
    config = {
        'issuer': mode.server.rstrip("/") + '/issuer',
        'token_endpoint': mode.server.rstrip("/") + '/issuer/token',
        'pre-authorized_grant_anonymous_access_supported': True
    }
    config.update(authorization_server_config)
    return Response(response=json.dumps(config), headers=headers)
    

def get_credential_offer(session_data):
    red = current_app.config["REDIS"]
    mode = current_app.config["MODE"]
    grant_type = session_data.get("grant_type")
    vc = session_data.get("vc")
    credential_identifier_list = list(vc.keys())
    offer = {
        'credential_issuer': f'{mode.server.rstrip("/")}/issuer',
        'credential_configuration_ids': credential_identifier_list,
    }
    if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
        offer['grants'] = {
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
                'pre-authorized_code': session_data.get("pre-authorized_code")
            }
        }
    else:
        logging.warning("Grant not supported for Agent")
        return None
    
    #prefix = "openid-credential-offer://?"
    id = str(uuid.uuid1())
    credential_offer_uri = f'{mode.server.rstrip("/")}/issuer/credential_offer_uri/{id}'
    red.setex(id, OFFER_LIFE, json.dumps(offer))
    logging.info('credential offer uri = %s', credential_offer_uri)
    encoded = quote(credential_offer_uri, safe="")
    return 'credential_offer_uri=' + encoded
    

# credential offer uri endpoint
def issuer_credential_offer_uri(id):
    red = current_app.config["REDIS"]
    try:
        offer = json.loads(red.get(id).decode())
    except Exception:
        logging.warning('session expired in credential offer uri endpoint')
        return jsonify({"error": "Session expired"}), 404
    return jsonify(offer), 201



# nonce endpoint
def issuer_nonce():
    red = current_app.config["REDIS"]
    nonce = str(uuid.uuid1())
    logging.info('Call of the nonce endpoint, nonce = %s', nonce)
    endpoint_response = {'c_nonce': nonce}
    red.setex(nonce, 60, 'nonce')
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(endpoint_response), headers=headers)


# token endpoint
def issuer_token():
    red = current_app.config["REDIS"]
    mode = current_app.config["MODE"]

    logging.info('token endoint header %s', request.headers)
    logging.info('token endoint form %s', json.dumps(request.form, indent=4))
    
    # display DPoP
    if request.headers.get('DPoP'):
        logging.info("DPoP hs been received i teh token reqqquest")
        try:
            DPoP_header = oidc4vc.get_header_from_token(request.headers.get('DPoP'))
            DPoP_payload = oidc4vc.get_payload_from_token(request.headers.get('DPoP'))
            logging.info('DPoP header = %s', json.dumps(DPoP_header, indent=4))
            logging.info('DPoP payload = %s', json.dumps(DPoP_payload, indent=4))
        except Exception as e:
            return Response(**manage_error('invalid_request', 'DPoP is incorrect ' + str(e), red, mode))
    else:
        logging.info('No DPoP has been received i teh token request')
    
    # check grant type
    grant_type = request.form.get('grant_type')
    if not grant_type:
        return Response(**manage_error('invalid_request', 'Request format is incorrect, grant is missing', red, mode))

    if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code' and not request.form.get('pre-authorized_code'):
        return Response(**manage_error('invalid_request', 'Request format is incorrect, this grant type is not supported', red, mode))

    if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
        code = request.form.get('pre-authorized_code')
    else:
        return Response(**manage_error('invalid_request', 'Grant type not supported', red, mode))
    
    # get data from code and check code validity
    try:
        data = json.loads(red.get(code).decode())
    except Exception:
        return Response(**manage_error('access_denied', 'Grant code expired', red, mode, status=404))
    
    if grant_type == 'authorization_code' and not request.form.get('redirect_uri'):
        return Response(**manage_error('invalid_request', 'Request format is incorrect, redirect_uri is missing', red, mode))

    # display client_authentication method
    if request.headers.get('Oauth-Client-Attestation'):
        client_authentication_method = 'client_attestation'
    elif request.headers.get('Authorization'):
        client_authentication_method = 'client_secret_basic'
    elif request.form.get('client_id') and request.form.get('client_secret'):
        client_authentication_method = 'client_secret_post'
    elif request.form.get('client_id'):
        client_authentication_method = 'client_id'
    else:
        client_authentication_method = 'none'
    logging.info('client authentication method = %s', client_authentication_method)
    
    # Check content of client assertion and proof of possession (PoP)
    if client_authentication_method == 'client_attestation':
        try:
            # https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-04.html
            client_assertion = request.headers['Oauth-Client-Attestation']
            PoP = request.headers['Oauth-Client-Attestation-Pop']
            logging.info('OAuth-Client-Attestation = %s', client_assertion)
            logging.info('OAuth-Client-Attestation-PoP = %s', PoP)
            if request.form.get('client_id') != oidc4vc.get_payload_from_token(client_assertion).get('sub'):
                return Response(**manage_error('invalid_request', 'client_id does not match client assertion subject', red, mode))
            if oidc4vc.get_payload_from_token(client_assertion).get('sub') != oidc4vc.get_payload_from_token(PoP).get('iss'):
                return Response(**manage_error('invalid_request', 'sub of client assertion does not match proof of possession iss', red, mode))
        except Exception:
            return Response(**manage_error('invalid_request', 'Headres is notr correct for client attestation', red, mode))

    # token endpoint response
    access_token = str(uuid.uuid1())
    refresh_token = str(uuid.uuid1())
    vc = data.get('vc')
    endpoint_response = {
        'access_token': access_token,
        'token_type': 'bearer',
        'expires_in': ACCESS_TOKEN_LIFE,
        'refresh_token': refresh_token
    }
    draft = data.get("draft")
    # add nonce in token endpoint response
    if draft <= 13:
        endpoint_response['c_nonce'] = str(uuid.uuid1())
        endpoint_response['c_nonce_expires_in'] = 1704466725
        red.setex(endpoint_response['c_nonce'], 600, 'nonce')
        
    # authorization_details in case of multiple VC of the same type
    authorization_details = []
    if draft >= 13 and isinstance(vc, list):
        for vc_type in vc:
            types = vc_type['types']
            vc_list = vc_type['list']
            identifiers = [one_vc['identifier'] for one_vc in vc_list]
            authorization_details.append(
                {
                    'type': 'openid_credential',
                    'format': 'jwt_vc_json',
                    'credential_definition': {
                        'type': types
                    },
                    'credential_identifiers': identifiers,
                }
            )
        logging.info('token endpoint response with authorization details')
        endpoint_response['authorization_details'] = authorization_details

    access_token_data = {
        'expires_at': datetime.timestamp(datetime.now()) + ACCESS_TOKEN_LIFE,
        'authorization_details': authorization_details,
        'client_id': request.form.get('client_id'),
        'scope': request.form.get('scope')
    }
    # add token endpoint response and code data to access token in Redis
    access_token_data.update(endpoint_response)
    access_token_data.update(data)
    red.setex(access_token, ACCESS_TOKEN_LIFE, json.dumps(access_token_data))
    red.setex(refresh_token, REFRESH_TOKEN_LIFE, json.dumps(access_token_data))
    
    # token endpoint response
    logging.info('token endpoint response = %s', json.dumps(endpoint_response, indent=4))
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(endpoint_response), headers=headers)


# credential endpoint
async def issuer_credential():
    red = current_app.config["REDIS"]
    mode = current_app.config["MODE"]
    manager = current_app.config["MANAGER"]
    logging.info('credential endoint header %s', request.headers)
    logging.info('credential endpoint request %s', json.dumps(request.json, indent=4))

    # DPoP
    if request.headers.get('DPoP'):
        logging.info("DPoP has been received i the credential request")
        try:
            DPoP_header = oidc4vc.get_header_from_token(request.headers.get('DPoP'))
            DPoP_payload = oidc4vc.get_payload_from_token(request.headers.get('DPoP'))
            logging.info('DPoP header = %s', json.dumps(DPoP_header, indent=4))
            logging.info('DPoP payload = %s', json.dumps(DPoP_payload, indent=4))
        except Exception as e:
            return Response(**manage_error('invalid_request', 'DPoP is incorrect ' + str(e), red, mode))
    else:
        logging.info('No DPoP has been received in the credential request')
        
    # Check access token
    try:
        access_token = request.headers['Authorization'].split()[1]
    except Exception:
        return Response(**manage_error('invalid_token', 'Access token not passed in request header', red, mode))
    
    # Get data
    try:
        access_token_data = json.loads(red.get(access_token).decode())
        issuer_metadata = access_token_data.get("issuer_metadata")
    except Exception:
        return Response(**manage_error('invalid_token', 'Access token expired', red, mode))
    
    draft = access_token_data.get("draft")
    
    # get agent identifier and type
    agent_identifier = access_token_data.get("agent_identifier")
    target_agent = access_token_data.get("target_agent")
    if agent_identifier.startswith("did:"):
        agent_identifier_type = "did"
    else:
        agent_identifier_type = "jwk"
    
    # Check request format
    try:
        result = request.json
    except Exception:
        return Response(**manage_error('invalid_request', 'Invalid request format', red, mode))

    # check vc format and credential_configuration_id
    vc_format = result.get('format')
    credential_configuration_id = None
    logging.info('format in credential request = %s', vc_format)
    if vc_format and vc_format not in ['ldp_vc', 'dc+sd-jwt', 'vc+sd-jwt']:
        return Response(**manage_error('unsupported_credential_format', 'Invalid VC format: ' + vc_format, red, mode))
    
    if draft in [13, 14]:
        if result.get('format') in ['dc+sd-jwt', 'vc+sd-jwt'] and not result.get('vct'):
            return Response(**manage_error('invalid_request', 'Invalid request format, vct is missing for vc+sd-jwt format', red, mode))
        elif result.get('format') in ['dc+sd-jwt', 'vc+sd-jwt']:
            pass
        else:
            try:
                credential_definition = result['credential_definition']
                type = credential_definition['type'] # to check if it exists
                context = credential_definition['@context'] # to check if it exists
            except Exception:
                return Response(**manage_error('invalid_request', 'Invalid request format, type or @context is missing for ldp_vc', red, mode))
    
    elif draft >= 15:
        if vc_format:
            logging.warning("format has been sent but OIDC4VCI draft is >= 15")
        credential_configuration_id = result.get('credential_configuration_id')
    else:
        pass    

    # get proof if it exists depending on type of proof and draft
    proof_type = None
    if result.get('proof'):   # all OIDC4VCI draft below Final
        proof_type = result["proof"].get('proof_type')
        proof = result["proof"].get("jwt") or result["proof"]. get("ldp_vp")
    elif result.get("proofs"): # Final 1.0
        for proof_type in ["jwt", "di_vp"]:
            if proof_type in result["proofs"]:
                proof = result["proofs"][proof_type][0]
                break 
    else:
        logging.warning("No proof found in the credential request")
        
    if proof_type == 'jwt':
        jwt_proof = proof
        proof_header = oidc4vc.get_header_from_token(jwt_proof)
        proof_payload = oidc4vc.get_payload_from_token(jwt_proof)
        logging.info('Proof header = %s', json.dumps(proof_header, indent=4))
        logging.info('Proof payload = %s', json.dumps(proof_payload, indent=4))
        if not proof_payload.get('nonce'):
            return Response(**manage_error('invalid_proof', 'c_nonce is missing', red, mode, status=403))
        
        try:
            oidc4vc.verif_token(jwt_proof)
            logging.info('proof is validated')
        except ValueError as e:
            logging.error(f"Proof verification failed: {e}")
            return Response(**manage_error('invalid_proof', 'Proof of key ownership, signature verification error: ' + str(e), red, mode, status=403))
        
        if not red.get(proof_payload['nonce']):
            logging.error('nonce does not exist')
        else:
            logging.info('nonce exists')
        
        if proof_header.get('jwk'): 
            wallet_jwk = proof_header.get('jwk')
        else:
            wallet_jwk = oidc4vc.resolve_did(proof_header.get('kid'))

        if access_token_data.get('client_id') and proof_payload.get("iss"):
            if proof_payload.get("iss") != access_token_data.get('client_id'):
                logging.error('iss %s of proof of key is different from client_id %s', proof_payload.get("iss") ,access_token_data.get('client_id') )
                return Response(**manage_error('invalid_proof', 'iss of proof of key is different from client_id', red, mode))
    
    elif proof_type in ['ldp_vp', 'di_vp']:
        wallet_jwk = None
        proof = json.dumps(proof) if isinstance(proof, dict) else proof
        proof_check = await didkit.verify_presentation(proof, '{}')
        logging.info('ldp_vp proof check  = %s', proof_check)
        if access_token_data.get("client_id") and agent_identifier and agent_identifier != access_token_data.get("client_id"):
            logging.warning('iss %s of proof of key is different from client_id %s', agent_identifier, access_token_data.get("client_id") )
            return Response(**manage_error('invalid_proof', 'iss of proof of key is different from client_id in token request', red, mode))
    else:
        return Response(**manage_error('invalid_proof', 'Proof type not supported', red, mode))
        
    logging.info("agent_identifier = %s", agent_identifier)
    logging.info('agent_identifier_type = %s', agent_identifier_type)
    logging.info('wallet_jwk = %s', wallet_jwk)

    # Get credential requested
    credential_identifier = None  # the credential identifier in the offer and issuer metadata
    if draft >= 15: # path pointer
        credential_identifier = credential_configuration_id
        issuer_metadata = build_issuer_metadata(mode)
        vc_format = issuer_metadata["credential_configurations_supported"][credential_identifier]["format"]
    
    elif draft in [13, 14]:
        credentials_supported_list = list(issuer_metadata['credential_configurations_supported'].keys())
        for vc in credentials_supported_list:
            if issuer_metadata['credential_configurations_supported'][vc]['vct'] == result.get('vct'):
                credential_identifier = vc
                break
        else:
            try:
                vc_type = result['credential_definition'].get('type')
            except Exception:
                logging.error("credential definition does not exist, wrong request format")
                return Response(**manage_error('invalid_request', 'credential definition not found', red, mode))
            vc_type.sort()
            for vc in credentials_supported_list:
                issuer_metadata['credential_configurations_supported'][vc]['credential_definition']['type'].sort()
                if issuer_metadata['credential_configurations_supported'][vc]['credential_definition']['type'] == vc_type:
                    credential_identifier = vc
                    break
    else:
        pass
    logging.info('credential type = %s', credential_identifier)
    
    if not credential_identifier:
        return Response(**manage_error('unsupported_credential_type', 'VC type not found', red, mode))
    
    logging.info('Only one VC of the same type = %s and format = %s', credential_identifier, vc_format)
    credential_payload = access_token_data['vc'][credential_identifier]
    
    # sign_credential(credential, wallet_did, issuer_id, c_nonce, format, issuer, mode, duration=365, wallet_jwk=None, wallet_identifier=None):
    if vc_format in ['vc+sd-jwt', 'dc+sd-jwt']:
        # add status list claim
        if access_token_data.get("status_list"):
            credential_payload['status'] = {
                'status_list': {
                    'idx': randint(0, 99999),
                    'uri': mode.server.rstrip("/") + '/issuer/statuslist/1'
                }
            }
        # sign sd-jwt vc
        credential_signed = oidc4vc.sign_sdjwt_by_agent(credential_payload, agent_identifier, target_agent, manager, draft=draft, duration=360*24*60*60)
    else:  # JSON-LD and JWT-VC
        credential_signed = await sign_jsonld_credential(credential_payload, target_agent, agent_identifier, access_token_data.get('c_nonce', 'nonce'),vc_format, mode.server)
    
    logging.info('credential signed sent to wallet = %s', credential_signed)
    if not credential_signed:
        return Response(**manage_error('internal_error', 'Credential signing error', red, mode))

    # Transfer VC
    c_nonce = str(uuid.uuid1())
    if draft >= 15:
        payload = {
            "credentials": [
                {
                    "credential":  credential_signed
                }
            ]
        }
    else:
        payload = {
            'credential': credential_signed,  # string or json depending on the format
            'c_nonce': c_nonce,
            'c_nonce_expires_in': C_NONCE_LIFE,
        }
    
    if draft < 13:
        payload.update({'format': vc_format})
    
    # update nonce in access token for next VC request
    access_token_data['c_nonce'] = c_nonce
    red.setex(access_token, ACCESS_TOKEN_LIFE, json.dumps(access_token_data))
        
    # send VC to wallet
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(payload), headers=headers)


async def sign_jsonld_credential(credential, target_agent, agent_identifier, duration, issuer_vm, issuer_key):
    if target_agent:
        credential['credentialSubject']['id'] = target_agent
    else:
        credential['credentialSubject'].pop('id', None)
    credential['id'] = 'urn:uuid:' + str(uuid.uuid1())
    try:
        credential['issuer']['id'] = agent_identifier
    except Exception:
        credential['issuer'] = agent_identifier
    credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + 'Z'
    credential['expirationDate'] = (datetime.now() + timedelta(days=duration)).replace(microsecond=0).isoformat() + 'Z'
    # manage remote context
    old_context = credential['@context']
    new_context = ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/ed25519-2020/v1"]
    for url in old_context:
        if isinstance(url, dict):
            new_context.append(url)
        elif url not in  ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/ed25519-2020/v1"]:
            remote_file = requests.get(url, timeout=10).json()
            new_context.append(remote_file['@context'])
        else:
            pass
    credential["@context"] = new_context
    try:
        didkit_options = {
            'proofPurpose': 'assertionMethod',
            'verificationMethod': issuer_vm,
        }
        if issuer_vm in ["did:web:app.altme.io:issuer#key-1",  "did:web:talao.co#key-4"]:
            didkit_options["type"] = "Ed25519Signature2020"
        credential_signed = await didkit.issue_credential(
            json.dumps(credential),
            didkit_options.__str__().replace("'", '"'),
            issuer_key,
        )
        credential_signed_json = json.loads(credential_signed)
        # re set original @context
        credential_signed_json["@context"] = old_context
        credential_signed = json.dumps(credential_signed_json)
    except Exception as e:
        logging.warning('Didkit exception = %s', str(e))
        logging.warning('incorrect json_ld = %s', json.dumps(credential))
        return
    logging.info('VC signed with didkit')
    #result = await didkit.verify_credential(credential_signed, '{}')
    #logging.info('signature check with didkit = %s', result)
    credential_signed = json.loads(credential_signed)
    return credential_signed