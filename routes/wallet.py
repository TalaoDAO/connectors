
from flask import Flask, request, jsonify, render_template, redirect, current_app
from flask_login import current_user, logout_user
import requests
from urllib.parse import urlencode,parse_qs, urlparse
import pkce
import logging
from datetime import datetime
from db_model import Wallet, Attestation, db,get_wallet_by_wallet_identifier
from utils import oidc4vc
import secrets
import json
from linked_vp import publish_linked_vp

logging.basicConfig(level=logging.INFO)


def init_app(app):
    
    # OAuth MCP server endpoint
    app.add_url_rule('/.well-known/oauth-protected-resource', view_func=protected_resource_metadata, methods=['GET'])
    app.add_url_rule('/.well-known/oauth-protected-resource/mcp', view_func=protected_resource_metadata, methods=['GET'])
    
    # OIDC4VCI wallet endpoint (oauth2 client)
    app.add_url_rule('/', view_func=wallet_route, methods=['GET'])
    app.add_url_rule('/wallets/<wallet_identifier>/credential_offer', view_func=credential_offer, methods=['GET', 'POST'])
    app.add_url_rule('/wallets/<wallet_identifier>/callback', view_func=callback, methods=['GET'])
    
    # OIDC4VP wallet endpoint (Oauth2 authorization server)
    app.add_url_rule('/wallets/<wallet_identifier>/authorize', view_func=authorize, methods=['GET', 'POST'])
    
    # openid configuration endpoint of the web wallet
    app.add_url_rule('/wallets/<wallet_identifier>/.well-known/openid-configuration', view_func=web_wallet_openid_configuration, methods=['GET'])
    app.add_url_rule('/.well-known/openid-configuration/wallets/<wallet_identifier>', view_func=web_wallet_openid_configuration, methods=['GET'])
    
    # wallet landing page
    app.add_url_rule('/wallets/<wallet_identifier>', view_func=wallet_landing_page, methods=['GET'])
    
    # user consent for credential offer / transaction_code
    app.add_url_rule('/wallets/<wallet_identifier>/user/consent', view_func=user_consent, methods=['POST'])
    app.add_url_rule('/wallets/<wallet_identifier>/user/tx_code', view_func=user_tx_code, methods=['POST'])
    
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
def web_wallet_openid_configuration(wallet_identifier):
    mode = current_app.config["MODE"]
    config = {
        "credential_offer_endpoint": mode.server  + "wallets/" + wallet_identifier + "/credential_offer",
        "authorization_endpoint": mode.server + "wallets/" + wallet_identifier + "/authorize"
    }
    return jsonify(config)

    
# endpoint for wallet landing page
def wallet_landing_page(wallet_identifier):
    w = get_wallet_by_wallet_identifier(wallet_identifier)
    message = "This data wallet is controlled by the AI Agent :" + w.agent_identifier + "."
    return render_template("wallet/session_screen.html", message=message, title="Welcome !")


# authorization endpoint of the wallet 
def authorize(wallet_identifier):
    """
    OIDC4VP / Self-Issued authorization endpoint for the wallet.

    It supports:
    - request:   JWT request object directly as query/form parameter
    - request_uri: URL pointing to the request object

    Flow:
    1. Retrieve and decode the OIDC4VP request object.
    2. Extract client_id, response_uri, nonce, state, etc.
    3. Select the wallet DID (holder).
    4. Build a Self-Issued id_token.
    5. POST (direct_post) the id_token ONLY to the response_uri endpoint.
    """
    manager = current_app.config["MANAGER"]
    w = get_wallet_by_wallet_identifier(wallet_identifier)
    agent_identifier = w.agent_identifier

    # 1. Get request / request_uri parameters
    req_jwt = request.args.get("request") or request.form.get("request")
    request_uri = request.args.get("request_uri") or request.form.get("request_uri")

    if not req_jwt and not request_uri:
        message = "Missing 'request' or 'request_uri' parameter in OIDC4VP authorization request."
        logging.warning(message)
        return render_template("wallet/session_screen.html", message=message, title="OIDC4VP Error")

    # If we only have a request_uri, fetch the request object from there
    if not req_jwt and request_uri:
        try:
            resp = requests.get(request_uri, timeout=10)
            resp.raise_for_status()
            # The endpoint may return a plain JWT or a JSON {"request": "<jwt>"}
            body_text = resp.text.strip()
        except Exception as e:
            logging.error("cannot fetch request from request_uri %s", request_uri)
            return jsonify({"error": str(e)}), 401
        try:
            body_json = resp.json()
            if isinstance(body_json, dict) and body_json.get("request"):
                req_jwt = body_json["request"]
            else:
                # Fallback: treat the whole body as JWT string
                req_jwt = body_text
        except Exception:
            # Not JSON => assume it's directly a compact JWS request object
            req_jwt = body_text
    
    # check signature
    try:
        oidc4vc.verif_token(req_jwt)
    except Exception as e:
        message = f"Request object has no valid signature: {str(e)}"
        logging.exception(message)
        return render_template("wallet/session_screen.html", message=message, title="OIDC4VP Error")
    
    # 2. Decode request object JWT
    try:
        req_header = oidc4vc.get_header_from_token(req_jwt)
        req_payload = oidc4vc.get_payload_from_token(req_jwt)
        logging.info("OIDC4VP request header = %s", req_header)
        logging.info("OIDC4VP request payload = %s", req_payload)
    except Exception as e:
        message = f"Request object is not a valid JWT: {str(e)}"
        logging.exception(message)
        return render_template("wallet/session_screen.html", message=message, title="OIDC4VP Error")

    # 3. Extract key parameters from request object
    client_id = (
        req_payload.get("client_id")
        or request.args.get("client_id")
        or request.form.get("client_id")
    )
    response_uri = (
        req_payload.get("response_uri")
        or req_payload.get("redirect_uri")
        or request.args.get("redirect_uri")
    )
    nonce = req_payload.get("nonce")
    state = req_payload.get("state") or request.args.get("state") or request.form.get("state")

    if not client_id:
        message = "client_id is missing in the OIDC4VP request object."
        logging.warning(message)
        return render_template("wallet/session_screen.html", message=message, title="OIDC4VP Error")

    if not response_uri:
        message = "response_uri is missing in the OIDC4VP request object (required for direct_post)."
        logging.warning(message)
        return render_template("wallet/session_screen.html", message=message, title="OIDC4VP Error")

    #check agent_identifier with aud
    aud = (
        request.args.get("aud")
        or request.form.get("aud")
        or req_payload.get("aud")
    )
    if aud != agent_identifier:
        message = "aud in authorization request is not correct."
        logging.warning(message)
        #return render_template("wallet/session_screen.html", message=message, title="OIDC4VP Error")

    # 5. Build a Self-Issued id_toke
    now = int(datetime.utcnow().timestamp())
    exp = now + 60*60  # 60 minutes validity

    wallet_kid = agent_identifier + "#key-1"
    key_id = manager.create_or_get_key_for_tenant(wallet_kid)
    jwk, kid, alg = manager.get_public_key_jwk(key_id)

    id_token_header = {
        "alg": alg,
        "typ": "JWT",
        "kid": wallet_kid,
    }

    id_token_payload = {
        "iss": agent_identifier,        # Self-issued: issuer is the wallet DID
        "sub": agent_identifier,        # Subject is also the wallet DID
        "aud": client_id,         # Audience is the verifier / client_id
        "iat": now,
        "exp": exp,
    }
    if nonce:
        id_token_payload["nonce"] = nonce

    # You can also include additional claims here if needed by your verifier
    # (e.g., "sub_jwk", "presentation_submission", etc.)

    try:
        id_token = manager.sign_jwt_with_key(key_id, header=id_token_header, payload=id_token_payload)
    except Exception as e:
        message = f"Failed to sign id_token: {str(e)}"
        logging.exception(message)
        return render_template("wallet/session_screen.html", message=message, title="OIDC4VP Error")
    
    logging.info("id token sent back by wallet for authentication request = %s", id_token)
    # 6. Send the Authentication Response by direct_post to response_uri
    post_data = {"id_token": id_token}
    if state:
        post_data["state"] = state

    try:
        resp = requests.post(
            response_uri,
            data=post_data,
            timeout=10,
        )
        logging.info("direct_post to response_uri returned status %s", resp.status_code)
        if 200 <= resp.status_code < 300:
            message = "Authentication response (id_token) has been sent successfully."
            title = "Authentication Sent"
        else:
            message = f"Authentication response failed with status code {resp.status_code}."
            title = "OIDC4VP Error"
    except Exception as e:
        logging.exception("direct_post to response_uri failed: %s", str(e))
        message = f"Authentication response could not be delivered: {str(e)}"
        title = "OIDC4VP Error"

    return render_template("wallet/session_screen.html", message=message, title=title)


def build_session_config(agent_id: str, credential_offer: dict, mode):
    this_wallet = Wallet.query.filter(Wallet.agent_identifier == agent_id).first()
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
    
    tx_code = False
    tx_code_description = None
    code = None
    issuer_state = None
    authorization_server_url = None
    if credential_offer['grants'].get('urn:ietf:params:oauth:grant-type:pre-authorized_code'):
        grant_type = 'urn:ietf:params:oauth:grant-type:pre-authorized_code'
        authorization_server_url = credential_offer['grants']['urn:ietf:params:oauth:grant-type:pre-authorized_code'].get("authorization_server")
        code = credential_offer['grants']['urn:ietf:params:oauth:grant-type:pre-authorized_code'].get('pre-authorized_code')
        if credential_offer['grants']['urn:ietf:params:oauth:grant-type:pre-authorized_code'].get('tx_code'):
            tx_code = True
            tx_code_description = credential_offer['grants']['urn:ietf:params:oauth:grant-type:pre-authorized_code']['tx_code'].get("description")
        if not code:
            logging.warning("no pre authorized code")
            return None, "No pre-authorized_code"
    elif credential_offer['grants'].get('authorization_code'):
        grant_type = "authorization_code"
        issuer_state = credential_offer['grants']['authorization_code'].get("issuer_state")
    else:
        return None, "OIDC4VCI grant is not supported"
        
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
        context = None
    else:
        type = credential_configuration['credential_definition']['type']
        context = credential_configuration['credential_definition'].get("@context", "")        
        vct = None
    scope = credential_configuration.get("scope")
    code_verifier, code_challenge = pkce.generate_pkce_pair()
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
        "@context": context,
        "type": type, # used for jwt_vc_json
        "vct": vct,  # used for vc+sd-jwt
        "grant_type": grant_type,
        "code": code,
        "issuer_state": issuer_state, 
        "code_verifier": code_verifier,
        "code_challenge": code_challenge,
        "state": secrets.token_urlsafe(32),
        "agent_identifier": this_wallet.agent_identifier,
        'is_DID': bool(this_wallet.did_document),
        "wallet_identifier": this_wallet.wallet_identifier,
        "wallet_url": this_wallet.url, # not used
        "wallet_profile": this_wallet.ecosystem_profile,
        "admins_login": json.loads(this_wallet.admins_login),
        "always_human_in_the_loop": this_wallet.always_human_in_the_loop,
        "server": mode.server,
        "tx_code": tx_code,
        "tx_code_description": tx_code_description
    }
    
    # mandatory fields
    mandatory_claims = ["credential_issuer", "token_endpoint", "credential_endpoint", "format"]
    if this_wallet.ecosystem_profile == "ARF":
        mandatory_claims.append("nonce_endpoint")
    for claim in mandatory_claims:
        if not session_config[claim]:
            logging.error("%s is missing in the session config", claim)
            return None, claim + ' is missing or unknown'
        
    if grant_type == "authorization_code" and not session_config["authorization_endpoint"]:
        return None, 'authorization endpoint is missing or unknown'
    
    logging.info("session_config = %s", session_config)
    return session_config, " ok "


# Entry point for tools from wallet for agent
def wallet(agent_id, credential_offer, mode, manager):
    session_config, text = build_session_config(agent_id, credential_offer, mode)
    if not session_config:
        return None, None, text
    if session_config["grant_type"] == 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
        attestation, text = code_flow(session_config, mode, manager)
        return session_config, attestation, text
    else:
        return session_config, None, "this grant type is not supported here"


# standard route to home
def wallet_route():
    return render_template("home.html")


# endpoint to request transaction id to user and get attestation in a pre authorzed flow with human in the loop
def user_tx_code(wallet_identifier):
    w = get_wallet_by_wallet_identifier(wallet_identifier)
    agent_identifier = w.agent_identifier
    red = current_app.config["REDIS"]
    manager = current_app.config["MANAGER"]
    mode = current_app.config["MODE"]
    session_id = request.form["session_id"]
    raw = red.get(session_id)
    if not raw:
        return render_template("wallet/session_expired.html")
    red.delete(session_id)
    session_config = json.loads(raw)
    session_config["tx_code_value"] = request.form.get("tx_code")
    sd_jwt_vc, text = code_flow(session_config, mode, manager)
    logout_user()
    if sd_jwt_vc:
        return render_template("wallet/user_consent.html", wallet_did=agent_identifier, sd_jwt_vc=sd_jwt_vc, title="Consent to Accept & Publish Attestation", session_id=session_id)
    else:
        logging.warning("sd jwt is missing %s", text)
        message = "The attestation cannot be issued"
        return render_template("wallet/session_screen.html", message=message, title="Sorry !")
 
    
# credential offer endpoint
def credential_offer(wallet_identifier):
    w = get_wallet_by_wallet_identifier(wallet_identifier)
    agent_identifier = w.agent_identifier
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
            # exit point to get transaction id from human
            if session_config["tx_code"]:
                return render_template("wallet/tx_code.html", session_id=session_id, wallet_did=agent_identifier)
            logout_user()   
            sd_jwt_vc, text = code_flow(session_config, mode, manager)
            if sd_jwt_vc:
                return render_template("wallet/user_consent.html", wallet_did=agent_identifier, sd_jwt_vc=sd_jwt_vc, title="Consent to Accept & Publish Attestation", session_id=session_id)
            else:
                logging.warning("sd jwt is missing %s", text)
                message = "The attestation cannot be issued"
                return render_template("wallet/session_screen.html", message=text, title="Sorry !")
    
    # First time, user is not logged
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
    this_wallet = Wallet.query.filter(Wallet.agent_identifier == agent_identifier).first()
    if not this_wallet:
        message = "Wallet not found"
        return render_template("wallet/session_screen.html", message=message, title= "Sorry !")
    
    session_config, text = build_session_config(this_wallet.agent_identifier, offer, mode)    
    if not session_config:
        logging.warning(" session config expired %s", text)
        message = "The attestation offer has expired"
        return render_template("wallet/session_screen.html", message=message, title="Sorry !")
    
    # if human is in the loop, wallet MUST redirect human to log in the agent wallet
    if session_config["always_human_in_the_loop"]:
        session_id = secrets.token_hex(16)
        red.setex(session_id, 1000, json.dumps(session_config))
        return redirect("/register?session_id=" + session_id)
    
    # if human not in the loop
    # it is an authorization code flow -> it is an exit point 
    if session_config["grant_type"] == "authorization_code":
        redirect_uri = build_authorization_request(session_config, red, mode)
        # send authorization request to issuer
        return redirect(redirect_uri)
    
    # it tx_code is required but human not in the loop.
    if session_config["tx_code"]:
        message = "This attestation cannot be issued as it requires a secret code and human is not in the loop."
        return render_template("wallet/session_screen.html", message=message, title="Sorry !")
    
    # get attestation
    attestation, message = code_flow(session_config, mode, manager)
    
    # store the attestation
    if attestation:
        result, message = store_and_publish(attestation, session_config, mode, manager, published=True)
        if result:
            message = "Attestation has been issued, stored and published successfully"
            return render_template("wallet/session_screen.html", message=message, title="Congrats !")
        else:
            message = "Attestation has been issued but not stored"
            return render_template("wallet/session_screen.html", message=message, title="Congrats !")
    
    logging.warning("no attestation")
    message = "The attestation issuance failed"
    return render_template("wallet/session_screen.html", message=message, title="Sorry !")


# route to request user consent then store the VC
def user_consent(wallet_identifier):
    mode = current_app.config["MODE"]
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
        result, message = store_and_publish(attestation, session_config, mode,  manager, published=True)
        if result:
            message = "Attestation has been issued, stored an published successfully"
            return render_template("wallet/session_screen.html", message=message, title= "Congrats !") 
        else:
            logging.warning(message)
            message = "Attestation cannot be issued"
            return render_template("wallet/session_screen.html", message=message, title= "Sorry !")
            
    else:
        result, message = store_and_publish(attestation, session_config, mode, manager, published=False)
        if result:
            message = "Attestation has been issued and stored successfully"
            return render_template("wallet/session_screen.html", message=message, title= "Congrats !") 
        else:
            logging.warning("attestation cannot be stored %s", message)
            return render_template("wallet/session_screen.html", message=message, title= "Sorry !")


def build_authorization_request(session_config, red, mode) -> str:
    authorization_endpoint = session_config['authorization_endpoint']
    data = {
        "redirect_uri": mode.server + "wallets/"  + session_config["wallet_identifier"] + "/callback",
        "client_id": session_config["agent_identifier"],
        "scope": session_config["scope"],
        "response_type": "code",
        "code_challenge": session_config["code_challenge"],
        "code_challenge_method": "S256",
        "state": session_config["state"] # wallet value if needed
    }
    if session_config.get("issuer_state"):
        data["issuer_state"] = session_config["issuer_state"]
    red.setex(session_config["state"], 1000, json.dumps(session_config))
    return f"{authorization_endpoint}?{urlencode(data)}"


# callback of the wallet as a client for OIDC4VCI authorization code flow
def callback(wallet_identifier):
    w = get_wallet_by_wallet_identifier(wallet_identifier)
    agent_identifier = w.agent_identifier
    logging.info('This is an authorized code flow')
    red = current_app.config["REDIS"]
    mode = current_app.config["MODE"]
    manager = current_app.config["MANAGER"]
    code = request.args.get('code')
    error = request.args.get("error", "")
    error_description = request.args.get("error_description", "")
    session_id = request.args.get("state")
    if error:
        logging.warning("error %s error_description %s", error, error_description)
        message = "The authorization response cannot be processed (session expired or invalid callback)."
        return render_template(
            "wallet/session_screen.html",
            message=message,
            title="Sorry !"
        )
    if not code:
        logging.warning("no code is the callbcak")
        # No code and no explicit error → malformed request
        message = "The authorization response cannot be processed (session expired or invalid callback)."
        return render_template(
            "wallet/session_screen.html",
            message=message,
            title="Sorry !"
        )
    try:
        raw = red.get(session_id)
        if not raw:
            raise ValueError("Session not found or expired")
        session_config = json.loads(raw.decode())
    except Exception as e:
        logging.warning("Callback issue: %s", e)
        message = "The authorization response cannot be processed (session expired or invalid callback)."
        return render_template(
            "wallet/session_screen.html",
            message=message,
            title="Sorry !"
        )
    # update session config with code from AS
    session_config["code"] = code
    logout_user()    
    
    # request token and credential
    sd_jwt_vc, text = code_flow(session_config, mode, manager)
    
    if sd_jwt_vc:
        return render_template("wallet/user_consent.html", wallet_did=agent_identifier, sd_jwt_vc=sd_jwt_vc, title="Consent to Accept & Publish Attestation", session_id=session_id)
    else:
        logging.warning("sd jwt is missing %s", text)
        message = "The attestation cannot be issued"
        return render_template("wallet/session_screen.html", message=text, title="Sorry !")
    


def token_request(session_config, mode):
    token_endpoint = session_config['token_endpoint']
    grant_type = session_config["grant_type"]

    data = {"grant_type": grant_type, "client_id": session_config["agent_identifier"]}

    if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
        data["pre-authorized_code"] = session_config["code"]
        # optional: only when required
        if session_config.get("tx_code") and session_config.get("tx_code_value"):
            data["tx_code"] = session_config["tx_code_value"]


    elif grant_type == 'authorization_code':
        data.update({
            "code": session_config["code"],
            "code_verifier": session_config["code_verifier"],
            "redirect_uri": mode.server + "wallets/" + session_config["wallet_identifier"] + "/callback"
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
    profile = session_config["wallet_profile"]
    if profile in ["DIIP V3", "DIIP V4", "EWC"]: 
        data = { 
            "proof": {
                "proof_type": "jwt",
                "jwt": proof
            }
        }
    else:  # profile in ["ARF"]:
        data = { 
            "proofs": {
                "jwt": [proof]
            }
        }
    if profile == "DIIP V3":
        data["format"] = session_config["format"]
        if data["format"] in ["jwt_vc_json"]:
            data["credential_definition"] = {
                "type": session_config.get("type")
            } 
        elif data["format"] in ["ldp_vc", "jwt_vc_json-ld"]:
            data["credential_definition"] = {
                "type": session_config.get("type"),
                "@context": session_config["@context"]
            }
        else:    
            data["vct"] = session_config.get("vct") 
    else:
        data["credential_configuration_id"] = session_config["credential_configuration_id"]
    
    #logging.info('credential endpoint request = %s', data)
    try:
        resp_json = requests.post(credential_endpoint, headers=headers, data = json.dumps(data), timeout=10).json()
        logging.info("credential endpoint response = %s", resp_json)
    except Exception as e:
        logging.warning("credentila request failure = %s", str(e))
        return None, "credential endpoint failure " + str(e)
    return resp_json, "ok"


def build_proof_of_key_ownership(session_config, nonce, manager):
    agent_identifier = session_config["agent_identifier"]
    wallet_kid = agent_identifier + "#key-1"
    key_id = manager.create_or_get_key_for_tenant(wallet_kid)
    jwk, kid, alg = manager.get_public_key_jwk(key_id)
    header = {
        'typ': 'openid4vci-proof+jwt',
        'alg': alg
    }
    payload = {
        'iss': agent_identifier,
        'iat': int(datetime.timestamp(datetime.now())),
        'aud': session_config["credential_issuer"]  # Credential Issuer URL
    }
    if session_config["wallet_profile"] in ["EWC","ARF"] or not session_config["is_DID"]:
        header["jwk"] = jwk
        header["jwk"].pop("kid", None)
    else:
        header["kid"] = wallet_kid
    if nonce:
        payload["nonce"] = nonce
    proof = manager.sign_jwt_with_key(key_id, header=header, payload=payload)
    return proof


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
    
    # get nonce
    nonce = token_endpoint_response.get("c_nonce")
    if not nonce:
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
        logging.warning("proof of key ownership failed %s", str(e))
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


def store_and_publish(cred, session_config, mode, manager, published=False):

    vc_format = session_config["format"]
    if vc_format in ["dc+sd-jwt", "vc+sd-jwt", "jwt_vc_json", "jwt_vc_json-ld"]:
        vcsd = cred.split("~") 
        vcsd_jwt = vcsd[0]
        try:
            attestation_payload = oidc4vc.get_payload_from_token(vcsd_jwt)
        except Exception:
            return None, "Attestation is in an incorrect format and cannot be stored"
        exp = datetime.fromtimestamp(attestation_payload.get("exp")) 
        issuer = attestation_payload.get("iss")
        if vc_format in ["dc+sd-jwt", "vc+sd-jwt"]:
            vct = attestation_payload.get("vct")
            name = attestation_payload.get("name","")
            description = attestation_payload.get("description","")
        elif vc_format in ["jwt_vc_json", "jwt_vc_json-ld"]:
            name = attestation_payload["vc"].get("name","")
            description = attestation_payload["vc"].get("description","")
            vct = json.dumps(attestation_payload["vc"].get("type", {})) # type
    
    elif vc_format == "ldp_vc":
        name = cred.get("name", "")
        description = cred.get("description","")
        vct = json.dumps(cred.get("type", {})) # type
        _exp = cred.get("issuanceDate")
        exp = datetime.strptime(_exp, "%Y-%m-%dT%H:%M:%SZ")
        issuer = cred.get("issuer", "")
        cred = json.dumps(cred)
        
    else:
        return None, "Attestation has no correct format and cannot be stored"

    # Publish attestation
    id = secrets.token_hex(16)
    service_id = session_config["agent_identifier"] + "#" + id
    if published:
        result = publish_linked_vp(
            service_id=service_id,
            attestation=cred,
            server=mode.server,
            mode=mode,
            manager=manager,
            vc_format=vc_format,
        )
        if not result:
            logging.warning("publish failed")
            published = False
    
    # Store attestation     
    attestation = Attestation(
            agent_identifier=session_config["agent_identifier"],
            wallet_identifier=session_config["wallet_identifier"],
            service_id=service_id,
            vc=cred,
            vc_format=vc_format,
            exp=exp,
            issuer=issuer,
            vct=vct,  # type = vct
            name=name,
            description=description,
            published=published
        )
    db.session.add(attestation)
    db.session.commit()
    if attestation: 
        logging.info("credential is stored as attestation #%s", attestation.id)
    
    return True, "Attestation has been stored"


