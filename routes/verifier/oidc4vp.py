
from flask import request, current_app
from flask import session, Response, jsonify, render_template
import json, base64
import uuid
import logging
from datetime import datetime, timedelta
from jwcrypto import jwk, jwt
from utils import oidc4vc, signer
import didkit
from db_model import Verifier, Credential, User, Wallet
from urllib.parse import  urlencode
import logging


logging.basicConfig(level=logging.INFO)
# customer application 
CODE_LIFE = 300

# wallet
QRCODE_LIFE = 300

# OpenID key of the OP for customer application
RSA_KEY_DICT = json.load(open("keys.json", "r"))['RSA_key']
rsa_key = jwk.JWK(**RSA_KEY_DICT) 
public_rsa_key = rsa_key.export(private_key=False, as_dict=True)

def init_app(app):
    # endpoints for wallet
    app.add_url_rule('/verifier/wallet/response',  view_func=verifier_response, methods=['POST']) # redirect_uri for DPoP/direct_post
    app.add_url_rule('/verifier/wallet/request_uri/<stream_id>',  view_func=verifier_request_uri, methods=['GET'])

    # to manage the verification through a link sent
    app.add_url_rule('/verification_email/<verif_id>',  view_func=verification_email, methods=['GET'])
    return


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def _json_compact(obj) -> bytes:
    # Canonical-ish JSON (no spaces, stable key order)
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

def build_jwt_request(account, credential_id, jwt_request, client_id_scheme) -> str:
    credential = Credential.query.filter(Credential.credential_id == credential_id).first()
    if not credential:
        return None

    header = {"typ": "oauth-authz-req+jwt"}  # RFC 9101 / OpenID specs
    if client_id_scheme == "x509_san_dns":
        header["x5c"] = json.loads(credential.x5c)
        public_key = json.loads(credential.public_key)
        header["alg"] = oidc4vc.alg(public_key)
    elif client_id_scheme == "verifier_attestation":
        header["jwt"] = credential.verifier_attestation
        public_key = json.loads(credential.public_key)
        header["alg"] = oidc4vc.alg(public_key)
    elif client_id_scheme == "redirect_uri":
        header["alg"] = "none"
    else:  # DID by default
        public_key = json.loads(credential.public_key)
        header["alg"] = oidc4vc.alg(public_key)
        header["kid"] = credential.verification_method

    payload = {
        "aud": "https://self-issued.me/v2",
        "exp": int(datetime.timestamp(datetime.now() + timedelta(seconds=1000))),
        **jwt_request,
    }

    if header["alg"] == "none":
        # Use the 2-segment unsecured form: <header>.<payload>
        h = _b64url(_json_compact(header))
        p = _b64url(_json_compact(payload))
        return f"{h}.{p}."
    else:
        # Your existing signer for JWS
        return signer.sign_jwt(account, credential, header, payload)

def build_verifier_metadata(verifier_id) -> dict:
    verifier = Verifier.query.filter(Verifier.application_api_verifier_id == verifier_id).one_or_none()
    if not verifier:
        logging.warning("verifier does not exist")
        return {}
    verifier_metadata = json.loads(verifier.verifier_metadata or "{}")
    logging.info("verifier metadata = %s", verifier_metadata)        
    return verifier_metadata


# build the authorization request                                      
def oidc4vp_qrcode(verifier_id, mcp_user_id, mcp_scope, red, mode):
    
    # to take into account the agent authentication use case
    if not mcp_user_id:
        mcp_user_id = str(uuid.uuid4())

    verifier = Verifier.query.filter(Verifier.application_api_verifier_id == verifier_id).one_or_none()
    logging.info("verifier name = %s", verifier.name)
    if not verifier:
        logging.warning("verifier not found: %s", verifier_id)
        return {"error": "unauthorized", "error_description": "Unknown verifier_id"}, 401

    if verifier.response_mode != "id_token" and not verifier.presentation and not body.get("presentation"):
        logging.warning("Presentation is not provided")
        return {"error": "invalid_request", "error_description": "A presentation object (PEX or DCQL) is required"}, 400

    # we dont use user_id as nonce
    nonce = str(uuid.uuid4()) # body["user_id"]

    # authorization request
    authorization_request = { 
        "client_id": verifier.client_id,
        "iss": verifier.client_id, # TODO
        "response_type": verifier.response_type,
        "response_uri": mode.server + "verifier/wallet/response",
        "response_mode": verifier.response_mode,
        "nonce": nonce
    }
        
    if 'vp_token' in verifier.response_type:              
        authorization_request["client_metadata"] = build_verifier_metadata(verifier_id)
        
        if verifier.presentation_format == "presentation_exchange":
            path = "presentation_exchange/"
            presentation_claim = "presentation_definition"
        else:
            path = "dcql_query/"
            presentation_claim = "dcql_query"
        fallback_presentation = json.load(open( path + "raw.json", "r"))
        if mcp_scope in ["email", "phone", "profile", "over18", "raw"]:
            authorization_request[presentation_claim] = json.load(open(path + mcp_scope + ".json", "r"))
        elif mcp_scope == "custom":
            authorization_request[presentation_claim] = json.loads(verifier.presentation) if verifier.presentation else fallback_presentation
        elif mcp_scope == "wallet_identifier":
            authorization_request['scope'] = 'openid'
            authorization_request["response_type"] = "id_token"
            authorization_request.pop("client_metadata", None)
        else:
            authorization_request[presentation_claim] = fallback_presentation
            
        authorization_request['aud'] = 'https://self-issued.me/v2'
        
        if verifier.client_id_scheme and int(verifier.draft) < 23:
            authorization_request["client_id_scheme"] = verifier.client_id_scheme

    # SIOPV2
    if 'id_token' in verifier.response_type:
        authorization_request['scope'] = 'openid'
    
    # store data in redis attached to the nonce to bind with the wallet response
    data = { 
        "verifier_id": verifier_id,
        "user_id": mcp_user_id,
        "mcp_scope": mcp_scope
    }
    data.update(authorization_request)
    red.setex(nonce, QRCODE_LIFE, json.dumps(data))
    red.setex(mcp_user_id, QRCODE_LIFE, json.dumps(data)) # fallback

    # NEW: initialize a pull status key for this flow (so we can detect expiry)
    red.setex(mcp_user_id + "_status", QRCODE_LIFE, json.dumps({"status": "pending"}))

    # signature key of the request object
    credential_id = verifier.credential_id

    # build the request object build_jwt_request(credential_id, request, client_id_scheme)
    user_id = verifier.user_id
    user = User.query.get_or_404(user_id)
    account = user.qtsp_account()
    request_as_jwt = build_jwt_request(account, credential_id, authorization_request, verifier.client_id_scheme)
    if not request_as_jwt:
        return "This verifier or key does not exist", 401

    logging.info("request as jwt = %s", request_as_jwt)

    # generate a request uri endpoint
    stream_id = str(uuid.uuid1())
    red.setex(stream_id, QRCODE_LIFE, request_as_jwt)

    # QRCode preparation with authorization_request_displayed
    authorization_request_for_qrcode = { 
        "client_id": verifier.client_id,
        "request_uri": mode.server + "verifier/wallet/request_uri/" + stream_id 
    }
    logging.info("authorization request = %s", json.dumps(authorization_request, indent= 4)  )

    url = verifier.prefix + '?' + urlencode(authorization_request_for_qrcode)
    verif_id = str(uuid.uuid4())
    red.setex(verif_id, 1000, url)
    return {
        "url": url,
        "poll_id": verif_id
    }

# build the authorization request                                      
def oidc4vp_agent_authentication(target_agent, agent_identifier, red, mode, manager):
    
    # to take into account the agent authentication use case
    mcp_user_id = str(uuid.uuid4())

    wallet = Wallet.query.filter(Wallet.did == agent_identifier).one_or_none()
    if not wallet:
        logging.warning("verifier not found: %s", agent_identifier)
        return {"error": "unauthorized", "error_description": "Unknown wallet did"}, 401

    # we dont use user_id as nonce
    nonce = str(uuid.uuid4()) # body["user_id"]

    # authorization request
    authorization_request = { 
        "client_id": agent_identifier,
        "iss": agent_identifier, # TODO
        "response_type": "id_token",
        "response_uri": mode.server + "verifier/wallet/response",
        "response_mode": "direct_post",
        "nonce": nonce,
        "aud": target_agent,
        "scope": "openid"
    }
        
    # store data in redis attached to the nonce to bind with the wallet response
    data = { 
        "verifier_id": agent_identifier,
        "user_id": target_agent,
        "mcp_scope": "wallet_identifier"
    }
    data.update(authorization_request)
    red.setex(nonce, QRCODE_LIFE, json.dumps(data))
    red.setex(mcp_user_id, QRCODE_LIFE, json.dumps(data)) # fallback

    # NEW: initialize a pull status key for this flow (so we can detect expiry)
    red.setex(mcp_user_id + "_status", QRCODE_LIFE, json.dumps({"status": "pending"}))
    
    vm = agent_identifier + "#key-1"
    key_id = manager.create_or_get_key_for_tenant(vm)
    jwk, kid, alg = manager.get_public_key_jwk(key_id)
    header = {
        "typ": "oauth-authz-req+jwt",
        "alg": alg,
        "kid": vm
    }
    request_as_jwt = manager.sign_jwt_with_key(key_id, header=header, payload=authorization_request)

    logging.info("request as jwt = %s", request_as_jwt)

    # generate a request uri endpoint
    stream_id = str(uuid.uuid1())
    red.setex(stream_id, QRCODE_LIFE, request_as_jwt)

    # QRCode preparation with authorization_request_displayed
    authorization_request_for_qrcode = { 
        "client_id": agent_identifier,
        "request_uri": mode.server + "verifier/wallet/request_uri/" + stream_id 
    }
    logging.info("authorization request = %s", json.dumps(authorization_request, indent= 4)  )

    oidc4vp_request = "openid4vp://?" + urlencode(authorization_request_for_qrcode)
    red.setex(nonce, 1000, json.dumps(authorization_request))
    return {
        "oidc4vp_request": oidc4vp_request,
    }
    

def verification_email(verif_id):
    red = current_app.config["REDIS"]
    uri = red.get(verif_id).decode()
    return  render_template("email_verification.html", uri=uri)


def verifier_request_uri(stream_id):
    red = current_app.config["REDIS"]
    try:
        payload = red.get(stream_id).decode()
    except Exception:
        return jsonify("Request no more available"), 408

    headers = { 
        "Content-Type": "application/oauth-authz-req+jwt",
        "Cache-Control": "no-cache"
    }
    return Response(payload, headers=headers)

def get_format(vp, type="vp"):
    if not vp:
        return
    elif isinstance(vp, dict):
        vp = json.dumps(vp)
    if vp[:1] == "{":
        return "ldp_" + type
    elif len(vp.split("~")) > 1:
        return "vc+sd-jwt"

async def verifier_response():
    red = current_app.config["REDIS"]
    logging.info("Enter wallet response endpoint")
    access = True

    # get if error
    if request.form.get('error'):
        response_data = {
            "error":  request.form.get('error'),
            "error_description": request.form.get('error_description')
        }
        logging.warning("wallet response error = %s", json.dumps(response_data, indent=4))
        access = False

    # get id_token, vp_token and presentation_submission
    if request.form.get('response'):
        response = oidc4vc.get_payload_from_token(request.form['response'])
        logging.info("direct_post.jwt")
    else:
        logging.info("direct_post")
        response = request.form

    vp_token = response.get('vp_token')
    id_token = response.get('id_token')
    presentation_submission = response.get('presentation_submission')

    if not vp_token:
        vp_token = ()
    elif vp_token and not presentation_submission:
        logging.error('No presentation submission received')
        access = False
    else:
        logging.info('presentation submission received = %s', presentation_submission)
        if isinstance(presentation_submission, str):
            presentation_submission = json.loads(presentation_submission)

    if id_token:
        logging.info('id token received from wallet')
        id_token_payload = oidc4vc.get_payload_from_token(id_token)

    vp_format = get_format(vp_token)   
    logging.info("VP format = %s", vp_format)   
    if vp_token and presentation_submission:
        logging.info('vp token received = %s', vp_token)
        vp_format_presentation_submission = presentation_submission["descriptor_map"][0]["format"]
        logging.info("VP format from presentation submission = %s", vp_format_presentation_submission)
        if vp_format not in ["vc+sd-jwt", "dc+sd-jwt", "ldp_vp"]:
            logging.error("vp format not supported")
            access = False
        elif vp_format != vp_format_presentation_submission:
            presentation_submission_status = "vp_format = " + vp_format + " but presentation submission vp_format = " + vp_format_presentation_submission
            logging.warning(presentation_submission_status)

    if not id_token and not vp_token:
        logging.error("invalid request format")
        access = False

    # check id_token signature
    if access and id_token:
        try:
            oidc4vc.verif_token(id_token)
        except Exception as e:
            logging.error(" id_token invalid format %s", str(e))
            access = False

    # look for claims and disclosures
    disclosure = {}
    claims = {}
    vp_token_list = None
    if access and vp_token:
        if vp_format == "vc+sd-jwt":
            vp_token_list = vp_token.split("~")
            
            # look for standard claims
            try:
                sdjwt_payload = oidc4vc.get_payload_from_token(vp_token_list[0])
                for c in sdjwt_payload:
                    if c not in ["_sd_alg", "cnf", "jti", "vct", "vct#integrity", "iat", "iss", "status", "exp", "_sd", "nonce", "sd_hash", "aud"]:
                        claims.update({c: sdjwt_payload.get(c)})
            except Exception:
                pass
            
            # look for disclosed claims
            nb_disclosure = len(vp_token_list)
            logging.info("nb of disclosure = %s", nb_disclosure - 2 )
            for i in range(1, nb_disclosure-1):
                _disclosure = vp_token_list[i]
                _disclosure += "=" * ((4 - len(_disclosure) % 4) % 4)
                try:
                    logging.info("disclosure #%s = %s", i, base64.urlsafe_b64decode(_disclosure.encode()).decode())
                    disc = json.loads(base64.urlsafe_b64decode(_disclosure.encode()).decode())
                    disclosure.update({disc[1]: disc[2]})
                except Exception:
                    logging.warning("i = %s", i)
                    logging.warning("_disclosure = %s", _disclosure)
        else: # ldp_vp
            verifyResult = json.loads(await didkit.verify_presentation(vp_token, "{}"))
            # TODO
            

    # get data from nonce binding
    nonce = None
    if vp_token:
        logging.info("cnf in vp_token = %s",oidc4vc.get_payload_from_token(vp_token_list[0])['cnf'])
        nonce = oidc4vc.get_payload_from_token(vp_token_list[-1])['nonce']
        try:
            vp_sub = oidc4vc.get_payload_from_token(vp_token_list[0])['cnf']["kid"]
        except Exception:
            vp_sub = oidc4vc.thumbprint(oidc4vc.get_payload_from_token(vp_token_list[-1])['cnf']["jwk"])
    elif id_token:
        nonce = oidc4vc.get_payload_from_token(id_token)['nonce']
        
    if not nonce:
        logging.warning("Missing or invalid nonce; cannot bind response")
        return jsonify({"error": "invalid_request", "error_description": "missing_nonce"}), 400
        
    try:
        data = json.loads(red.get(nonce).decode())
        user_id = data["user_id"]
    except Exception:
        logging.warning("Missing or invalid nonce; cannot bind response")
        return jsonify({"error": "invalid_request", "error_description": "missing_nonce"}), 400
    
    status_code = 200 if access else 400
    if status_code == 400:
        response = {
            "error": "access_denied"
        }
        logging.warning("Access denied")
    else:
        response = {}

    # follow up
    if id_token:
        sub = id_token_payload.get('sub')
    else:
        try:
            sub = vp_sub
        except Exception:
            sub = "Error"

    # data for MCP client
    wallet_data = {"credential_status":"VALID", "scope": data["mcp_scope"]}
    if data["mcp_scope"] == "wallet_identifier":
        wallet_data["wallet_identifier"] = sub
        
    wallet_data.update(disclosure)
    wallet_data.update(claims)
    if data["mcp_scope"] == "raw":
        wallet_data["raw"] = request.form
        
    red.setex(user_id + "_wallet_data", CODE_LIFE, json.dumps(wallet_data))

    # Update pull status for MCP clients
    red.setex(user_id + "_status", CODE_LIFE, json.dumps({"status": "verified" if access else "denied"}))

    return jsonify(response), status_code


# ------------- Pull -------------
def wallet_pull_status(user_id, red):
    # uer email  or target agent
    
    try:
        data = json.loads(red.get(user_id).decode())
    except Exception:
        return {"status":"not_found","user_id":user_id}
    
    verifier_id = data.get("verifier_id")    
    verifier = Verifier.query.filter(Verifier.application_api_verifier_id == verifier_id).one_or_none()
    if not verifier:
        logging.warning("verifier not found: %s", verifier_id)
        return {"error": "unauthorized", "error_description": "Unknown verifier_id"}
    
    # Fetch status first
    status_raw = red.get(user_id + "_status")
    if not status_raw:
        return {"status": "not_found", "user_id": user_id}
    try:
        status = json.loads(status_raw.decode()).get("status", "pending")
    except Exception:
        status = "pending"

    if status == "pending":
        return {"status": "pending", "user_id": user_id}

    # verified or denied -> try to include wallet_data if present
    wd_raw = red.get(user_id + "_wallet_data")
    wallet_data = None
    if wd_raw:
        try:
            wallet_data = json.loads(wd_raw.decode())
        except Exception:
            wallet_data = {"raw": wd_raw.decode(errors="ignore")}
    
    response = {
        "status": status,
        "id": id,
    }
    if wallet_data is not None:
        response.update(wallet_data)
    return response