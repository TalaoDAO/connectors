
from flask import Flask, request, jsonify, render_template, redirect, current_app
from flask_login import current_user, logout_user
import requests
from urllib.parse import urlencode,parse_qs, urlparse
import pkce
import logging
from datetime import datetime
from db_model import Wallet, Attestation, db
from utils import oidc4vc
import secrets
import json
import base64
import hashlib

logging.basicConfig(level=logging.INFO)


def init_app(app):
    
    # OAuth MCP server endpoint
    app.add_url_rule('/.well-known/oauth-protected-resource', view_func=protected_resource_metadata, methods=['GET'])
    app.add_url_rule('/.well-known/oauth-protected-resource/mcp', view_func=protected_resource_metadata, methods=['GET'])
    
    
    # OIDC4VCI wallet endpoint
    app.add_url_rule('/', view_func=wallet_route, methods=['GET'])
    app.add_url_rule('/<wallet_did>/credential_offer', view_func=credential_offer, methods=['GET'])
    app.add_url_rule('/callback', view_func=callback, methods=['GET', 'POST'])
    
    # openid configuration endpoint of the web wallet
    app.add_url_rule('/did/<wallet_did>/.well-known/openid-configuration', view_func=web_wallet_openid_configuration, methods=['GET'])
    app.add_url_rule('/.well-known/openid-configuration/did/<wallet_did>', view_func=web_wallet_openid_configuration, methods=['GET'])
    
    # wallet landing page
    app.add_url_rule('/did/<wallet_did>', view_func=wallet_landing_page, methods=['GET'])
    
    # user consent for credential offer
    app.add_url_rule('/user/consent', view_func=user_consent, methods=['POST'])
    
    return

# MCP server endpoint
def protected_resource_metadata():
    # https://www.rfc-editor.org/rfc/rfc9728.html
    mode = current_app.config["MODE"]
    config = {
        "resource": mode.server + "mcp",
        "bearer_method_supported": ["header"],
        "tls_client_certificate_bound_access_tokens": True,
        "authorization_servers": [mode.server]
    }
    return jsonify(config)

# openid configuration endpoint for web wallet 
def web_wallet_openid_configuration(wallet_did):
    mode = current_app.config["MODE"]
    config = {
        "credential_offer_endpoint": mode.server  + wallet_did + "/credential_offer"
        #"authorization_endpoint": mode.server + "/authorize"
    }
    return jsonify(config)

    
# endpoint for wallet landing page
def wallet_landing_page(wallet_did):
    message = "This data wallet is controlled by the AI Agent :" + wallet_did + "."
    return render_template("wallet/session_screen.html", message=message, title="Welcome !")


def build_session_config(agent_id: str, credential_offer, mode):
    this_wallet = Wallet.query.filter(Wallet.did == agent_id).one_or_none()
    if not this_wallet:
        logging.warning("wallet not found")
        return None, "wallet not found"
    if isinstance(credential_offer, dict):
        pass
    elif isinstance(credential_offer, str):
        parse_result = urlparse(credential_offer)
        result = {k: v[0] for k, v in parse_qs(parse_result.query).items()}
        if result:
            if credential_offer_uri := result.get('credential_offer_uri'):
                try:
                    credential_offer = requests.get(credential_offer_uri, timeout=10).json()
                except Exception:
                    return None, "credential_offer_uri endpoint not available"
            else:
                try:
                    credential_offer = json.loads(result.get('credential_offer', '{}'))
                except Exception:
                    return None, "credential_offer is in incorrect format"
        else:
            # try to parse the whole string as JSON
            try:
                credential_offer = json.loads(credential_offer)
            except Exception:
                return None, "credential_offer is in incorrect format"

    else:
        return None, "credential_offer is in incorrect format"
    
    credential_issuer = credential_offer.get('credential_issuer')
    
    if not credential_offer.get("grants"):
        return None, "credential_offer is in incorrect format"
    
    if credential_offer['grants'].get('urn:ietf:params:oauth:grant-type:pre-authorized_code'):
        grant_type = 'urn:ietf:params:oauth:grant-type:pre-authorized_code'
        authorization_server_url = credential_offer['grants']['urn:ietf:params:oauth:grant-type:pre-authorized_code'].get("authorization_server")
        issuer_state = None
        try:
            code = credential_offer['grants'].get('urn:ietf:params:oauth:grant-type:pre-authorized_code', [{}])['pre-authorized_code']
        except Exception:
            logging.warning("no pre authorized code")
            return None, "No pre-authorized_code"
    elif credential_offer['grants'].get('authorization_code'):
        authorization_server_url = None
        grant_type = "authorization_code"
        issuer_state = credential_offer['grants']['authorization_code'].get("issuer_state")
        code = None
    else:
        return None, "OIDC4VCI flow is not defined"
        
    # one take only the first one
    credential_configuration_id = credential_offer['credential_configuration_ids'][0]
    
    issuer_config_url = credential_issuer + '/.well-known/openid-credential-issuer'
    issuer_config_json = requests.get(issuer_config_url, timeout= 10).json()
    if not authorization_server_url:
        authz_srv = issuer_config_json.get("authorization_server")
        if isinstance(authz_srv, list) and authz_srv:
            authorization_server_url = authz_srv[0]
        elif isinstance(authz_srv, str) and authz_srv.strip():
            authorization_server_url = authz_srv.strip()
        else:
            authorization_server_url = credential_issuer
    try:
        authorization_server_config = requests.get(authorization_server_url + '/.well-known/oauth-authorization-server', timeout=10).json()
    except Exception:
        # fallback
        authorization_server_url = credential_issuer + '/.well-known/oauth-authorization-server'
        try:
            authorization_server_config = requests.get(authorization_server_url, timeout=10).json()
        except Exception:
            return None, "authorization server not available"
    
    credential_configuration = issuer_config_json['credential_configurations_supported'][credential_configuration_id]    
    format = credential_configuration.get('format')  
    if format in ["vc+sd-jwt", "dc+sd-jwt"]:
        vct = credential_configuration.get("vct")
        type = None
    else:
        type = credential_configuration['credential_definition']['type']
        vct = None
    scope = credential_configuration.get("scope")
    session_config = {
        "credential_issuer": credential_issuer,
        "authorization_endpoint": authorization_server_config.get('authorization_endpoint'),
        "pushed_authorization_request_endpoint": authorization_server_config.get("pushed_authorization_request_endpoint"),
        "token_endpoint": authorization_server_config.get('token_endpoint'),
        "nonce_endpoint": issuer_config_json.get("nonce_endpoint"),
        "credential_endpoint": issuer_config_json.get("credential_endpoint"),
        "deferred_credential_endpoint": issuer_config_json.get("deferred_credential_endpoint"),
        "notification_endpoint": issuer_config_json.get("notification_endpoint"),
        "credential_configuration_id": credential_configuration_id,
        "format": format,
        "scope": scope,
        "type": type,  # not used
        "vct": vct,  # not used
        "grant_type": grant_type,
        "code": code,
        "issuer_state": issuer_state,  # not used
        "wallet_did": this_wallet.did,
        "wallet_url": this_wallet.url, # not used
        "owners_login": json.loads(this_wallet.owners_login),
        "always_human_in_the_loop": this_wallet.always_human_in_the_loop,
        "server": mode.server
    }
    
    # mandatory fields
    for claim in ["credential_issuer", "token_endpoint", "credential_endpoint", "format", "scope"]:
        if not session_config[claim]:
            logging.error("%s is missing in the session config", claim)
            return None, claim + ' is missing or unknown'
        
    if grant_type == "authorization_code" and not session_config["authorization_endpoint"]:
        return None, 'authorization endpoint is missing or unknown'
    
    logging.info("session_config = %s", session_config)
    return session_config, " ok "


# for MCP tools
def wallet(agent_id, credential_offer, mode, manager):
    session_config, text = build_session_config(agent_id, credential_offer, mode)
    if not session_config:
        return None, text
    if session_config["grant_type"] == 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
        attestation, text = code_flow(session_config, mode, manager)
        return attestation, text
    else:
        return None, "this grant type is not supported here"

# standard route to home
def wallet_route():
    return render_template("home.html")
    
    
# credential offer endpoint
def credential_offer(wallet_did):
    red = current_app.config["REDIS"]
    mode = current_app.config["MODE"]
    manager = current_app.config["MANAGER"]
    
    # if user is logged -> human in the loop
    if current_user.is_authenticated:
        logging.info("user is now logged")
        session_id = request.args.get("session_id")
        if not session_id:
            logout_user()
            message = "This session expired"
            return render_template("wallet/session_screen.html", message=message, title="Sorry !")
        raw = red.get(session_id)
        if not raw:
            logout_user()
            logging.warning("session expired")
            message = "This attestation offer has expired"
            return render_template("wallet/session_screen.html", message=message, title="Sorry !")
        session_config = json.loads(raw.decode())
        if session_config["grant_type"] == "authorization_code":
            redirect_uri = build_authorization_request(session_config, red, mode)
            # send authorization request to issuer
            return redirect(redirect_uri)
        
        # the user is logged, it is a pre authorized code flow and we ask user for consent 
        else:
            sd_jwt_vc, text = code_flow(session_config, mode, manager)
            logout_user()
            if sd_jwt_vc:
                return render_template("wallet/user_consent.html", sd_jwt_vc=sd_jwt_vc, title="Consent to Accept & Publish Attestation", session_id=session_id)
            else:
                logging.warning("sd jwt is missing %s", text)
                message = "The attestation cannot be issued"
                return render_template("wallet/session_screen.html", message=text, title="Sorry !")
    
    # if user is not logged
    logging.info("user is not logged") 
    # get credential offer
    if credential_offer_uri := request.args.get('credential_offer_uri'):
        try:
            offer = requests.get(credential_offer_uri, timeout=10).json()
        except Exception as e:
            logging.warning("session expired %s", str(e))
            message = "The attestation offer has expired"
            return render_template("wallet/session_screen.html", message=message, title="Sorry !")
    elif offer := request.args.get('credential_offer'):
        try:
            offer = json.loads(offer)
        except Exception as e:
            logging.warning("session expired %s", str(e))
            message = "The attestation offer has expired"
            return render_template("wallet/session_screen.html", message=message, title="Sorry !")
    else:
        logging.warning("incorrect VC format")
        message = "This credential format is not supported."
        return render_template("wallet/session_screen.html", message=message, title="Sorry !")
            
    # build session config and store it in memory for next call to the same endpoint
    wallet = Wallet.query.filter(Wallet.did == wallet_did).one_or_none()
    if not wallet:
        message = "Wallet not found"
        return render_template("wallet/session_screen.html", message=message, title= "Sorry !")
    
    session_config, text = build_session_config(wallet.did, offer, mode)    
    if not session_config:
        logging.warning(" session config expired %s", text)
        message = "The attestation offer has expired"
        return render_template("wallet/session_screen.html", message=message, title="Sorry !")
    
    # if human is in the loop -> redirect user to registration
    if session_config["always_human_in_the_loop"]:
        session_id = secrets.token_hex(16)
        red.setex(session_id, 1000, json.dumps(session_config))
        return redirect("/register?session_id=" + session_id)
    
    # if human not in the loop and pre authorized code flow
    if session_config["grant_type"] == 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
        attestation, message = code_flow(session_config, mode, manager)
        if attestation:
            # store attestation
            result, message = store_and_publish(attestation, session_config, manager, published=True)
            if result:
                message = "Attestation has been issued, stored and published successfully"
                return render_template("wallet/session_screen.html", message=message, title="Congrats !")
            else:
                message = "Attestation has been issued but not stored"
                return render_template("wallet/session_screen.html", message=message, title="Congrats !")
        
        logging.warning("no attestation")
        message = "The attestation issuance failed"
        return render_template("wallet/session_screen.html", message=message, title="Sorry !")
    
    # if human not in the loop and authorization code flow
    else:
        logging.warning("attestation is missing %s", message)
        message = "This attestation cannot been issued without human consent."
        return render_template("wallet/session_screen.html", message=message, title= "Sorry !")


# route to request user consent then store the VC
def user_consent():
    decision = request.form.get('decision')
    if decision == "reject":
        message = "Attestation has been rejected"
        return render_template("wallet/session_screen.html", message=message, title="Well done!") 

    red = current_app.config["REDIS"]
    manager = current_app.config["MANAGER"]
    attestation = request.form.get("sd_jwt_vc")
    session_id = request.form.get("session_id")
    public_url = request.form.get("publish_scope") or None
    try:
        raw = red.get(session_id)
        if not raw:
            raise ValueError("Session expired or not found")
        session_config = json.loads(raw.decode())
    except Exception as e:
        logging.exception("User consent session issue: %s", str(e))
        message = "This attestation session has expired. Please start again from the attestation offer."
        return render_template("wallet/session_screen.html", message=message, title="Sorry !")

    if public_url == "public":
        result, message = store_and_publish(attestation, session_config, manager, published=True)
        if result:
            message = "Attestation has been issued, stored an published successfully"
            return render_template("wallet/session_screen.html", message=message, title= "Congrats !") 
        else:
            logging.warning(message)
            message = "Attestation cannot be issued"
            return render_template("wallet/session_screen.html", message=message, title= "Sorry !")
            
    else:
        result, message = store_and_publish(attestation, session_config, manager, published=False)
        if result:
            message = "Attestation has been issued and stored successfully"
            return render_template("wallet/session_screen.html", message=message, title= "Congrats !") 
        else:
            logging.warning("attestation cannot be stored %s", message)
            return render_template("wallet/session_screen.html", message=message, title= "Sorry !")


def build_authorization_request(session_config, red, mode) -> str:
    authorization_endpoint = session_config['authorization_endpoint']
    code_verifier, code_challenge = pkce.generate_pkce_pair()
    state = secrets.token_urlsafe(32)

    data = {
        "redirect_uri": mode.server + "callback",
        "client_id": session_config["wallet_did"],
        "scope": session_config["scope"],
        "response_type": "code",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state
    }
    session_config.update({"code_verifier": code_verifier, "state": state})
    red.setex(state, 1000, json.dumps(session_config))
    return f"{authorization_endpoint}?{urlencode(data)}"


# callback du wallet for authorization code flow
def callback():
    logging.info('This is an authorized code flow')
    red = current_app.config["REDIS"]
    mode = current_app.config["MODE"]
    manager = current_app.config["MANAGER"]
    
    try:
        code = request.args['code']
        session_id = request.args.get('state', "")
        raw = red.get(session_id)
        if not raw:
            raise ValueError("Session not found or expired")
        session_config = json.loads(raw.decode())
    except Exception as e:
        logging.exception("Callback issue: %s", e)
        message = "The authorization response cannot be processed (session expired or invalid callback)."
        return render_template(
            "wallet/session_screen.html",
            message=message,
            title="Sorry !"
        )
    
    # update session config with code from AS
    session_config["code"] = code
    logout_user()    
    sd_jwt_vc, text = code_flow(session_config, mode, manager)
    if not sd_jwt_vc:
        return render_template("wallet/session_screen.html", message=text, title="Issuance Failure")
    return render_template(
        "wallet/user_consent.html",
        sd_jwt_vc=sd_jwt_vc,
        title="Consent to Accept & Publish Attestation",
        session_id=session_id
    )


def token_request(session_config, mode):
    token_endpoint = session_config['token_endpoint']
    grant_type = session_config["grant_type"]

    data = {"grant_type": grant_type, "client_id": session_config["wallet_did"]}

    if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
        data["pre-authorized_code"] = session_config["code"]
    elif grant_type == 'authorization_code':
        data.update({
            "code": session_config["code"],
            "code_verifier": session_config["code_verifier"],
            "redirect_uri": mode.server + "callback"
        })
    else:
        return None, "grant type is unknown"

    try:
        resp_json = requests.post(token_endpoint, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data=data, timeout=10).json()
    except Exception as e:
        logging.error("Request error = %s", str(e))
        return None, f"Request error {e}"

    if "error" in resp_json:
        return None, resp_json.get("error_description", resp_json.get("error", "token_error"))

    return resp_json, "ok"


def credential_request(session_config, access_token, proof):
    credential_endpoint = session_config['credential_endpoint']
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token
        }
    
    data = { 
        "proof": {
            "proof_type": "jwt",
            "jwt": proof
        },
        "credential_configuration_id": session_config["credential_configuration_id"]
    }

    #logging.info('credential endpoint request = %s', data)
    try:
        resp_json = requests.post(credential_endpoint, headers=headers, data = json.dumps(data), timeout=10).json()
    except Exception as e:
        return None, "credential endpoint failure " +str(e)
    logging.info("credential endpoint response = %s", resp_json)
    
    return resp_json, "ok"


def build_proof_of_key_ownership(session_config, nonce, manager):
    wallet_did = session_config["wallet_did"]
    wallet_kid = wallet_did + "#key-1"
    key_id = manager.create_or_get_key_for_tenant(wallet_kid)
    jwk, kid, alg = manager.get_public_key_jwk(key_id)
    header = {
        'typ': 'openid4vci-proof+jwt',
        'alg': alg,
        "kid": wallet_kid
    }
    payload = {
        'iss': wallet_did,
        'iat': int(datetime.timestamp(datetime.now())),
        'aud': session_config["credential_issuer"]  # Credential Issuer URL
    }
    if nonce:
        payload["nonce"] = nonce
    jwt_token = manager.sign_jwt_with_key(key_id, header=header, payload=payload)
    return jwt_token


# process code flow
def code_flow(session_config, mode, manager):
    # access token request
    token_endpoint_response, text = token_request(session_config, mode)
    logging.info('token endpoint response = %s', token_endpoint_response)
    
    if not token_endpoint_response:
        logging.warning('token endpoint error return code = %s', token_endpoint_response)
        return None, text

    # access token received
    access_token = token_endpoint_response.get("access_token")
    if not access_token:
        return None, "access token missing"
    try:
        nonce_endpoint_url = session_config["nonce_endpoint"]
        headers = {'Authorization': f'Bearer {access_token}'}
        result = requests.post(nonce_endpoint_url, headers=headers, timeout=10).json()
        nonce = result.get("c_nonce")
    except Exception as e:
        return None, str(e)
        
    #build proof of key ownership
    try:
        proof = build_proof_of_key_ownership(session_config, nonce, manager)
    except Exception as e:
        return None, str(e)
    logging.info("proof of key ownership sent = %s", proof)

    # credential request
    result, text = credential_request(session_config, access_token, proof)
    if not result:
        return None, text
    if result.get('error'):
        logging.warning('credential endpoint error return code = %s', result)
        return None, result.get("error_description")
    
    # get the first the credential only
    cred = None
    if isinstance(result, dict):
        if "credentials" in result and result["credentials"]:
            cred = result["credentials"][0].get("credential")
        elif "credential" in result:
            cred = result.get("credential")
    if not cred:
        return None, "credential missing in response"
        
    logging.info("credential endpoint response = %s", result)    
    return cred, "ok"


def store_and_publish(cred, session_config, manager, published=False):
    # store attestation
    vcsd = cred.split("~") 
    vcsd_jwt = vcsd[0]
    try:
        attestation_header = oidc4vc.get_header_from_token(vcsd_jwt)
        attestation_payload = oidc4vc.get_payload_from_token(vcsd_jwt)
    except Exception:
        return None, "Attestation is in an incorrect format and cannot be stored"

    # attestation as a service id
    id = secrets.token_hex(16)
    service_id = session_config["wallet_did"] + "#" + id
    
    if published:
        result = publish(service_id, cred, session_config["server"], manager)
        if not result:
            logging.warning("publish failed")
            published = False
            
    attestation = Attestation(
            wallet_did=session_config["wallet_did"],
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
    db.session.commit()
    if attestation: 
        logging.info("credential is stored as attestation #%s", attestation.id)
    
    return True, "Attestation has been stored"


# helper: base64url without padding
def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def publish(service_id, attestation, server, manager):

    # 1. Look up wallet did and id
    wallet_did = service_id.split("#")[0]
    id = service_id.split("#")[1]
    
    this_wallet = Wallet.query.filter(Wallet.did == wallet_did).one_or_none()
    if this_wallet is None:
        logging.error("Wallet not found for DID %s", wallet_did)
        return None

    # 2. Load existing DID Document
    try:
        did_document = json.loads(this_wallet.did_document or "{}")
    except Exception:
        logging.exception("Invalid DID Document in wallet")
        return None

    # 3. Normalize / validate incoming SD-JWT VC presentation (SD-JWT)
    sd_jwt_presentation = attestation.strip()
    if not sd_jwt_presentation.endswith("~"):
        sd_jwt_presentation = sd_jwt_presentation + "~"

    # remove disclosure if any
    sd_jwt_plus_kb = sign_and_add_kb(sd_jwt_presentation, wallet_did, manager)
    if not sd_jwt_plus_kb:
        return None

    # 6. Wrap into a VC Data Model 2.0-style Verifiable Presentation envelope
    #    Using media type application/dc+sd-jwt in a data: URI.
    vp_resource = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation", "EnvelopedVerifiablePresentation"],
        "id": "data:application/dc+sd-jwt," + sd_jwt_plus_kb,
    }

    try:
        linked_vp_json = json.loads(this_wallet.linked_vp or "{}")
    except Exception:
        linked_vp_json = {}

    linked_vp_json[id] = vp_resource
    this_wallet.linked_vp = json.dumps(linked_vp_json)

    # 8. Create LinkedVerifiablePresentation service endpoint in DID Doc
    service_array = did_document.get("service", [])
    
    new_service = {
        "id": service_id,
        "type": "LinkedVerifiablePresentation",
        "serviceEndpoint": server + "service/" + wallet_did + "/" + id,
    }

    service_array.append(new_service)
    did_document["service"] = service_array
    this_wallet.did_document = json.dumps(did_document)

    # 9. Persist changes
    db.session.commit()
    logging.info("attestation is published")

    # Optionally return details for caller
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
    