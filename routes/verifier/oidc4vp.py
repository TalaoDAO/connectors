
from flask import request, current_app
from flask import session, Response, jsonify
import json, base64
import uuid
import logging
from datetime import datetime, timedelta
import requests
from jwcrypto import jwk, jwt
from utils import oidc4vc, signer
import didkit
from db_model import Verifier, Credential, User, db
from urllib.parse import urlparse, urlencode
from utils.kms import decrypt_json
import logging


logging.basicConfig(level=logging.INFO)
# customer application 
ACCESS_TOKEN_LIFE = 2000
CODE_LIFE = 2000

# wallet
QRCODE_LIFE = 2000

# OpenID key of the OP for customer application
RSA_KEY_DICT = json.load(open("keys.json", "r"))['RSA_key']
rsa_key = jwk.JWK(**RSA_KEY_DICT) 
public_rsa_key = rsa_key.export(private_key=False, as_dict=True)

def init_app(app):
    # endpoints for wallet
    app.add_url_rule('/verifier/wallet/callback',  view_func=verifier_response, methods=['POST']) # redirect_uri for DPoP/direct_post
    app.add_url_rule('/verifier/wallet/request_uri/<stream_id>',  view_func=verifier_request_uri, methods=['GET'])
    # NEW: pull endpoint for MCP clients (replace webhooks)
    app.add_url_rule('/verifier/wallet/pull/<session_id>', view_func=wallet_pull_status, methods=['GET'])
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


# API to build the authorization request                                      
def oidc4vp_qrcode(red, mode):
    #red = current_app.config["REDIS"]
    #mode = current_app.config["MODE"]
    
    print("mode server dans oidc4vp = ", mode.server)
        
    # --- Auth ---
    request_api_key = request.headers.get("X-API-KEY")
    if not request_api_key:
        return {"error": "unauthorized", "error_description": "Missing X-API-KEY"}, 401
    
    body = request.get_json(silent=True) or {}
    if not body:    
        logging.error("Data must be a json object")
        return {"error": "invalid_request", "error_description": "data must be a JSON object"}, 400
    
    verifier_id = body.get("verifier_id")
    if not verifier_id:
        return {"error": "invalid_request", "error_description": "issuer_id missing"}, 400    
    
    verifier = Verifier.query.filter(Verifier.application_api_verifier_id == verifier_id).one_or_none()
    if not verifier:
        logging.warning("verifier not found: %s", verifier_id)
        return {"error": "unauthorized", "error_description": "Unknown verifier_id"}, 401

    if not request_api_key == decrypt_json(verifier.application_api)["verifier_secret"]:
        return {"error": "unauthorized"}, 401

    # RELAXED: Do NOT require webhook_url when using pull model (still allowed if provided)
    if verifier.response_mode != "id_token" and not verifier.presentation and not body.get("presentation"):
        logging.warning("Presentation is not provided")
        return {"error": "invalid_request", "error_description": "A presentation object (PEX or DCQL) is required"}, 400

    if not body.get("session_id"):
        return {"error": "invalid_request", "error_description": "session_id is required"}, 401

    session_id = body["session_id"]
    nonce = str(uuid.uuid1())

    # authorization request
    authorization_request = { 
        "client_id": verifier.client_id,
        "iss": verifier.client_id, # TODO
        "response_type": verifier.response_type,
        "response_uri": mode.server + "verifier/wallet/callback",
        "response_mode": verifier.response_mode,
        "nonce": nonce
    }
    authorization_request["client_metadata"] = build_verifier_metadata(verifier_id)

    # OIDC4VP
    mcp_scope = body.get("scope")
    if 'vp_token' in verifier.response_type:
        if verifier.presentation_format == "presentation_exchange":
            if mcp_scope in ["email", "phone", "profile", "over18"]:
                presentation_request = json.load(open("presentation_exchange/" + mcp_scope + ".json", "r"))
            else:    
                presentation_request = json.loads(verifier.presentation) if verifier.presentation else body.get("presentation", {})
            authorization_request['presentation_definition'] = presentation_request
        else:
            if mcp_scope == "profile":
                presentation_request = json.load(open("dcql_query/profile.json", "r")) 
            else:    
                presentation_request = json.loads(verifier.presentation) if verifier.presentation else body.get("presentation", {})
            authorization_request['dcql_query'] = presentation_request
            
        authorization_request['aud'] = 'https://self-issued.me/v2'
        
        if verifier.client_id_scheme:
            authorization_request["client_id_scheme"] = verifier.client_id_scheme
    else:
        presentation_request = {}

    # SIOPV2
    if 'id_token' in verifier.response_type:
        authorization_request['scope'] = 'openid'
    
    if not mcp_scope: # -> "wallet_identifier":
        authorization_request['scope'] = 'openid'
        authorization_request["response_type"] = "id_token"
        authorization_request.pop("presentation_definition", None)
        authorization_request.pop("client_metadata", None)
    
    # store data in redis attached to the nonce to bind with the response
    data = { 
        "verifier_id": verifier_id,
        "session_id": session_id,
        "mcp_scope": mcp_scope
    }
    data.update(authorization_request)
    red.setex(nonce, QRCODE_LIFE, json.dumps(data))

    # NEW: initialize a pull status key for this flow (so we can detect expiry)
    red.setex(session_id + "_status", QRCODE_LIFE, json.dumps({"status": "pending"}))

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
    logging.info(json.dumps(authorization_request_for_qrcode, indent= 4)  )

    url = verifier.prefix + '?' + urlencode(authorization_request_for_qrcode)

    return ({
        "url": url,
        "session_id": session_id
    })

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
    logging.info("Header = %s", request.headers)
    logging.info("Form = %s", request.form)
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
            logging.info("presentation submission is a string")
        else:
            logging.info("presentation submission is a dict /json object")

    if id_token:
        logging.info('id token received = %s', id_token)
        id_token_payload = oidc4vc.get_payload_from_token(id_token)
    else:
        logging.info("id_token not received")

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
                    logging.info("i = %s", i)
                    logging.info("_disclosure = %s", _disclosure)
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
        session_id = data["session_id"]
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

    # data for MCP client or webhook (To be defined)
    if data["mcp_scope"]:
        wallet_data = {
            "credential_status": "VALID", # INVALID , SUSPENDED
            "scope": data["mcp_scope"]
        }
    else:
        wallet_data = {"wallet_identifier": sub}
        
    wallet_data.update(disclosure)
    wallet_data.update(claims)
    red.setex(session_id + "_wallet_data", CODE_LIFE, json.dumps(wallet_data))

    # Update pull status for MCP clients
    red.setex(session_id + "_status", CODE_LIFE, json.dumps({"status": "verified" if access else "denied"}))

    return jsonify(response), status_code


# ------------- Pull endpoint -------------
def wallet_pull_status(session_id: str):
    """Return the current status for a given session_id.
    Responses:
      200 verified/denied -> include wallet_data (tokens redacted should be done by caller if needed)
      202 pending         -> still waiting for wallet
      404 not_found       -> unknown or expired flow
    """
    red = current_app.config["REDIS"]

    # Fetch status first
    status_raw = red.get(session_id + "_status")
    if not status_raw:
        return jsonify({"status": "not_found", "session_id": session_id}), 404
    try:
        status = json.loads(status_raw.decode()).get("status", "pending")
    except Exception:
        status = "pending"

    if status == "pending":
        return jsonify({"status": "pending", "session_id": session_id}), 202

    # verified or denied -> try to include wallet_data if present
    wd_raw = red.get(session_id + "_wallet_data")
    wallet_data = None
    if wd_raw:
        try:
            wallet_data = json.loads(wd_raw.decode())
        except Exception:
            wallet_data = {"raw": wd_raw.decode(errors="ignore")}
    
    response = {
        "status": status,
        "session_id": session_id,
    }
    response.update(wallet_data)
    return jsonify(response), 200
