
import base64
from flask import Flask, request, jsonify, render_template, redirect, session, current_app
from flask_login import login_required, current_user, logout_user
from jwcrypto import jwk, jwt
import requests
import json
import sys
from urllib.parse import urlencode
import pkce
import logging
from datetime import datetime
logging.basicConfig(level=logging.INFO)
import uuid
import copy
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse
from db_model import Wallet, Attestation, db
from utils import deterministic_jwk, oidc4vc
import secrets

# wallet key for testing purpose

KEY_DICT = {
    "kty": "EC",
    "d": "d_PpSCGQWWgUc1t4iLLH8bKYlYfc9Zy_M7TsfOAcbg8",
    "crv": "P-256",
    "x": "ngy44T1vxAT6Di4nr-UaM9K3Tlnz9pkoksDokKFkmNc",
    "y": "QCRfOKlSM31GTkb4JHx3nXB4G_jSPMsbdjzlkT_UpPc",
    "alg": "ES256",
}
wallet_key = jwk.JWK(**KEY_DICT)
KEY_DICT['kid'] = wallet_key.thumbprint()
pub_key = copy.copy(KEY_DICT)
del pub_key['d']


pub_key_json = json.dumps(pub_key).replace(" ", "")
DID = "did:jwk:" + base64.urlsafe_b64encode(pub_key_json.encode()).decode().replace("=", "")
VM = DID + "#0"


def init_app(app):
    app.add_url_rule('/', view_func=wallet_route, methods=['GET'])
    app.add_url_rule('/<wallet_did>/credential_offer', view_func=credential_offer, methods=['GET'])
    app.add_url_rule('/callback', view_func=callback, methods=['GET', 'POST'])
    
    app.add_url_rule('/did/<wallet_did>/.well-known/openid-configuration', view_func=web_wallet_openid_configuration, methods=['GET'])
    app.add_url_rule('/.well-known/openid-configuration/did/<wallet_did>', view_func=web_wallet_openid_configuration, methods=['GET'])
    
    app.add_url_rule('/user/consent', view_func=user_consent, methods=['GET', 'POST'])
    
    return

def get_configuration():
    f = open("wallet_configuration.json", 'r')
    return json.loads(f.read())


def web_wallet_openid_configuration(wallet_did):
    mode = current_app.config["MODE"]
    config = {
        "credential_offer_endpoint": mode.server  + wallet_did + "/credential_offer"   
    }
    return jsonify(config)


def build_session_config(agent_id: str, credential_offer: str):
    this_wallet = Wallet.query.filter(Wallet.did == agent_id).one_or_none()
    if not this_wallet:
        logging.warning("wallet not found")
        return None, "wallet not found"
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
    
    if not isinstance(credential_offer, dict):
        credential_offer = json.loads(credential_offer)
    
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
        if issuer_config_json.get("authorization_server"):
            authorization_server_url = issuer_config_json.get("authorization_server")[0]
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
        "type": type,
        "vct": vct,
        "grant_type": grant_type,
        "code": code,
        "issuer_state": issuer_state,
        "wallet_did": this_wallet.did,
        "wallet_url": this_wallet.url,
        "owner_login": this_wallet.owner_login,
        "always_human_in_the_loop": this_wallet.always_human_in_the_loop
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
def wallet(agent_id, credential_offer, mode):
    session_config, text = build_session_config(agent_id, credential_offer)
    if not session_config:
        return None, text
    if session_config["grant_type"] == 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
        attestation, text = code_flow(session_config, mode)
        return attestation, text
    else:
        return None, "this grant type is not supported here"

# standard route to home
def wallet_route():
    return render_template("home.html")
    
    
# credntial offer endpoint
def credential_offer(wallet_did):
    red = current_app.config["REDIS"]
    mode = current_app.config["MODE"]
    # if user is logged (user in the loop)
    if current_user.is_authenticated:
        logging.info("user is now logged")
        session_id = request.args.get("session_id")
        if not session_id:
            logout_user()
            message = "This session expired"
            return render_template("wallet/session_screen.html", message=message, title="Access Denied")
        raw = red.get(session_id)
        if not raw:
            logout_user()
            message = "This session expired"
            return render_template("wallet/session_screen.html", message=message, title="Access Denied")
        session_config = json.loads(raw.decode())
        if session_config["grant_type"] == "authorization_code":
            redirect_uri = build_authorization_request(session_config, red, mode)
            # send authorization request to issuer
            return redirect(redirect_uri)
        
        # the user is logged, it is a pre authorized code flow and we ask user for consent 
        else:
            sd_jwt_vc, text = code_flow(session_config, mode)
            logout_user()
            if sd_jwt_vc:
                return render_template("wallet/user_consent.html", sd_jwt_vc=sd_jwt_vc, title="Consent to Accept & Publish Attestation", session_id=session_id)
            else:
                return render_template("wallet/session_screen.html", message=text, title="Issuance Failure")
    
    # user is not logged
    logging.info("user is not logged") 
    # get credential offer
    if credential_offer_uri := request.args.get('credential_offer_uri'):
        try:
            offer = requests.get(credential_offer_uri, timeout=10).json()
        except Exception:
            message = "The issuer session expired"
            return render_template("wallet/session_screen.html", message=message, title="Issuance Failure")
    elif offer := request.args.get('credential_offer'):
        try:
            offer = json.loads(offer)
        except Exception:
            message = "The issuer session expired"
            return render_template("wallet/session_screen.html", message=message, title="Issuance Failure")
    else:
        message = "Incorrect credential format"
        return render_template("wallet/session_screen.html", message=message, title="Issuance Failure")
            
    # build session config and store it in memory for next call to the same endpoint
    wallet = Wallet.query.filter(Wallet.did == wallet_did).one_or_none()
    if not wallet:
        message = "Wallet not found"
        return render_template("wallet/session_screen.html", message=message, title= "Access Denied")
    
    session_config, text = build_session_config(wallet.did, json.dumps(offer))    
    if not session_config:
        return render_template("wallet/session_screen.html", message=text, title="Access Denied")
    
    # if user in the loop, redirect user to regisration
    if session_config["always_human_in_the_loop"]:
        session_id = secrets.token_hex(16)
        red.setex(session_id, 1000, json.dumps(session_config))
        return redirect("/register?session_id=" + session_id)
    
    # no user in the loop, Start the pre authorized code flow only
    if session_config["grant_type"] == 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
        attestation, text = code_flow(session_config, mode)
        if attestation:
            message = "Attestation has been issued"
            return render_template("wallet/session_screen.html", message=message, title= "Congrats !")        
        return render_template("wallet/session_screen.html", message=text, title= "Issuance failed")
    else:
        message = "Grant type not supported"
        return render_template("wallet/session_screen.html", message=message, title= "Issuance Failure")


# route to request user consent then store the VC
def user_consent():
    decision = request.form.get('decision')
    if decision == "reject":
        message = "Attestation has been rejected"
        return render_template("wallet/session_screen.html", message=message, title= "Well done!") 
    red = current_app.config["REDIS"]
    attestation = request.form.get("sd_jwt_vc")
    session_id = request.form.get("session_id")
    public_url = request.form.get("publish_scope") or None
    session_config = json.loads(red.get(session_id).decode())
    store(attestation, session_config)
    if public_url == "public":
        message = "Attestation has been stored an published"
    else:
        message = "Attestation has been stored"
    return render_template("wallet/session_screen.html", message=message, title= "Congrats !") 


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
    try:
        code = request.args['code']
        session_id = request.args.get('state', "")
        session_config = json.loads(red.get(session_id).decode())
    except Exception:
        return jsonify({"error": "callback issue"})
    
    # update session config with code from AS
    session_config["code"] = code
    logout_user()    
    sd_jwt_vc, text = code_flow(session_config, mode)
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


def build_proof_of_key_ownership(session_config, nonce):
    wallet_did = session_config["wallet_did"]
    wallet_kid = wallet_did + "#key-1"
    key = deterministic_jwk.jwk_p256_from_passphrase(wallet_kid)
    signer_key = jwk.JWK(**key) 
    header = {
        'typ': 'openid4vci-proof+jwt',
        'alg': key.get("alg", "ES256"),
        "kid": wallet_kid
    }
    payload = {
        'iss': wallet_did,
        'iat': int(datetime.timestamp(datetime.now())),
        'aud': session_config["credential_issuer"]  # Credential Issuer URL
    }
    if nonce:
        payload["nonce"] = nonce  
    token = jwt.JWT(header=header, claims=payload, algs=['ES256'])
    token.make_signed_token(signer_key)
    return token.serialize()


# process code flow
def code_flow(session_config, mode):
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
        proof = build_proof_of_key_ownership(session_config, nonce)
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


def store(cred, session_config):
    # store attestation
    vcsd = cred.split("~")
    vcsd_jwt = vcsd[0]
    try:
        attestation_header = oidc4vc.get_header_from_token(vcsd_jwt)
        attestation_payload = oidc4vc.get_payload_from_token(vcsd_jwt)
    except Exception:
        return None, "attestation is in an incorrect format"
    attestation = Attestation(
            wallet_did=session_config["wallet_did"],
            vc=cred,
            vc_format=attestation_header.get("typ"),
            issuer=attestation_payload.get("iss"),
            vct=attestation_payload.get("vct"),
            name=attestation_payload.get("name",""),
            description=attestation_payload.get("description","")
        )
    db.session.add(attestation)
    db.session.commit()
    logging.info("credential is stored as attestation #%s", attestation.id)
    return True, "ok"