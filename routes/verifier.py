
from flask import request, current_app
from flask import Response, jsonify, render_template
import json, base64
import uuid
from jwcrypto import jwk
from utils import oidc4vc
import didkit
from db_model import Wallet
from urllib.parse import  urlencode
import logging


logging.basicConfig(level=logging.INFO)
# customer application 
CODE_LIFE = 300
POLL_LIFE = 300

# wallet
QRCODE_LIFE = 300

# OpenID key of the OP for customer application
RSA_KEY_DICT = json.load(open("keys.json", "r"))['RSA_key']
rsa_key = jwk.JWK(**RSA_KEY_DICT) 
public_rsa_key = rsa_key.export(private_key=False, as_dict=True)

def init_app(app):
    
    # wallet as an OAuth 2 client (verifier) in an OIDC4VP flow
    app.add_url_rule('/verifier/response',  view_func=verifier_response, methods=['POST']) # redirect_uri for DPoP/direct_post
    app.add_url_rule('/verifier/request_uri/<stream_id>',  view_func=verifier_request_uri, methods=['GET'])

    # to manage the verification through a link sent
    app.add_url_rule('/verification_email/<url_id>',  view_func=verification_email, methods=['GET'])

    # polling endpoint for email verification / web pages
    app.add_url_rule('/verifier/pull/<id>', view_func=verifier_pull, methods=['GET'])
    return


# build the authorization request for user                                   
def user_verification(agent_identifier, red, mode, manager):
    # configure verifier from ecosystem profile
    wallet = Wallet.query.filter(Wallet.agent_identifier == agent_identifier).first()
    #wallet_identifier = wallet.wallet_identifier
    profile = wallet.ecosystem_profile
    logging.info("profile  %s", profile)
    request_uri_method = None 
    if profile == "DIIP V5":
        request_uri_method = "get"
        draft = 28
        presentation_format = "dcql_query"
        client_id = agent_identifier
    elif profile in ["ARF", "EUDIW"]:
        request_uri_method = "get"
        draft = 30
        presentation_format = "dcql_query"
        client_id = "redirect_uri:" + wallet.url
    elif profile == "DIIP V3":
        draft = 20
        presentation_format = "presentation_exchange"
        client_id = agent_identifier
    else: # ebsi
        draft = 20
        presentation_format = "presentation_exchange"
        client_id = wallet.url
        
    # we dont use user_id as nonce
    nonce = str(uuid.uuid4()) # body["user_id"]

    # authorization request
    authorization_request = { 
        "client_id": client_id,
        "iss": agent_identifier,
        "response_type": "vp_token",
        "response_uri": mode.server + "verifier/response",
        "response_mode": "direct_post",
        "nonce": nonce
    }
    response_type = ["vp_token"]
    if 'vp_token' in response_type:         
        if presentation_format == "presentation_exchange":
            path = "presentation_exchange/"
            presentation_claim = "presentation_definition"
        else:
            path = "dcql_query/"
            presentation_claim = "dcql_query"
        
        authorization_request[presentation_claim] = json.load(open(path + "profile.json", "r"))
        if request_uri_method:
            authorization_request["request_uri_method"] = request_uri_method
        authorization_request['aud'] = 'https://self-issued.me/v2'
        
        if draft < 23:
            authorization_request["client_id_scheme"] = "did"
    
    # store data in redis attached to the nonce to bind with the wallet response
    verification_request_id = str(uuid.uuid4())
    data = { 
        "request_type": "user_verification",
        "agent": agent_identifier,
        "verification_request_id": verification_request_id
    }
    data.update(authorization_request)
    red.setex(nonce, QRCODE_LIFE, json.dumps(data))

    # initialize a pull status key for this flow
    red.setex(verification_request_id + "_status", POLL_LIFE, json.dumps({"status": "pending"}))
    red.setex(agent_identifier + "_status", POLL_LIFE, json.dumps({"status": "pending"}))

    # prepare request as jwt
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
        "request_uri": mode.server + "verifier/request_uri/" + stream_id 
    }
    if request_uri_method:
        authorization_request_for_qrcode["request_uri_method"] = request_uri_method
        
    logging.info("authorization request = %s", json.dumps(authorization_request, indent=2)  )

    url = 'openid-vc://?' + urlencode(authorization_request_for_qrcode)
    url_id = str(uuid.uuid4())
    red.setex(url_id, 1000, json.dumps({"uri": url, "request_id": verification_request_id}))
    
    return {
        "url": url,
        "url_id": url_id,
        "verification_request_id": verification_request_id
    }

# build the authorization request  for agent                                    
def agent_authentication(target_agent, agent_identifier, red, mode, manager):
    
    # we take the first wallet of this agent
    wallet = Wallet.query.filter_by(agent_identifier=agent_identifier).first()
    if not wallet:
        return
    wallet_identifier = wallet.wallet_identifier  # unique
    
    authentication_request_id = str(uuid.uuid4())
    nonce = str(uuid.uuid4())

    # authorization request
    authorization_request = { 
        "client_id": agent_identifier,
        "iss": agent_identifier, # TODO
        "response_type": "id_token",
        "response_uri": mode.server + "verifier/response",
        "response_mode": "direct_post",
        "nonce": nonce,
        "aud": target_agent,
        "scope": "openid"
    }
        
    # store data in redis attached to the nonce to bind with the wallet response
    data = {
        "request_type": "agent_authentication",
        "target_agent": target_agent,
        "target_wallet": wallet_identifier,
        "agent": agent_identifier,
        "authentication_request_id": authentication_request_id
    }
    data.update(authorization_request)
    red.setex(nonce, QRCODE_LIFE, json.dumps(data))
    
    # set status to pending immediately
    red.setex(authentication_request_id + "_status", QRCODE_LIFE, json.dumps({"status": "pending"}))
    red.setex(agent_identifier + "_status", QRCODE_LIFE, json.dumps({"status": "pending"}))
    
    # prepare request as jwt
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
        "request_uri": mode.server + "verifier/request_uri/" + stream_id 
    }
    logging.info("authorization request = %s", json.dumps(authorization_request, indent= 4)  )

    oidc4vp_request = "openid-vc://?" + urlencode(authorization_request_for_qrcode)
    return {
        "target_agent": target_agent,
        "target_wallet": wallet_identifier,
        "oidc4vp_request": oidc4vp_request,
        "authentication_request_id": authentication_request_id
    }
    
# endpoint to display the verifier QR code
def verification_email(url_id):
    red = current_app.config["REDIS"]
    try:
        raw = red.get(url_id)
        if not raw:
            raise Exception('missing')
        raw = raw.decode()
    except Exception:
        return render_template("wallet/session_expired.html")

    # Backward compatible: value may be plain uri or JSON {uri, request_id}
    uri = None
    request_id = None
    try:
        obj = json.loads(raw)
        uri = obj.get("uri") or obj.get("url")
        request_id = obj.get("request_id") or obj.get("verification_request_id")
    except Exception:
        uri = raw

    return render_template("wallet/email_verification.html", uri=uri, request_id=request_id)


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



# polling endpoint
def verifier_pull(id):
    red = current_app.config["REDIS"]
    return jsonify(wallet_pull_status(id, red))


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

    # look for claims from disclosures
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
                    claims.update({disc[1]: disc[2]})
                except Exception:
                    logging.warning("i = %s", i)
                    logging.warning("_disclosure = %s", _disclosure)
        else: # ldp_vp
            verifyResult = json.loads(await didkit.verify_presentation(vp_token, "{}"))
            # TODO
            

    # fetch nonce for binding
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
    
    # get data from nonce
    try:
        nonce_data = json.loads(red.get(nonce).decode())
        red.delete(nonce)
        request_type = nonce_data.get("request_type")
        logging.info("it is a response for an %s", request_type)
        request_id = ( nonce_data.get("authentication_request_id") or nonce_data.get("verification_request_id"))
        agent_identifier = nonce_data.get("agent")
    
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

    # wallet data received for user verification
    if request_type == "user_verification":
        wallet_data = {"scope": "profile"}
        for c in ["given_name", "family_name", "birth_date"]:
            if claims.get(c):
                wallet_data.update({c: claims.get(c)})   
        # Store user data in Redis
        red.setex(request_id + "_wallet_data", POLL_LIFE, json.dumps(wallet_data))
        # fallback
        red.setex(agent_identifier + "_last_user_verification_wallet_data", POLL_LIFE, json.dumps(wallet_data))
        

    # Store status for user and agents in Redis
    red.setex(request_id + "_status", POLL_LIFE, json.dumps({"status": "verified" if access else "denied"}))
    # fallback
    if request_type == "user_verification":
        red.setex(agent_identifier + "_last_user_verification" + "_status", POLL_LIFE, json.dumps({"status": "verified" if access else "denied"}))
    else:
        red.setex(agent_identifier + "_last_agent_authentication" + "_status", POLL_LIFE, json.dumps({"status": "verified" if access else "denied"}))      

    return jsonify(response), status_code


# ------------- Pull -------------
# unique for target agent and user by email verification
def wallet_pull_status(id, red):
    # user email  or target agent
    logging.info("call poll status for id = %s", id)
    # Fetch status first
    status_raw = red.get(id + "_status")
    if not status_raw:
        return {"status": "not_found"}
    try:
        status = json.loads(status_raw.decode()).get("status", "pending")
    except Exception:
        status = "pending"

    if status == "pending":
        return {"status": status}
    elif status == "denied":
        return {"status": status}

    # verified -> try to include wallet_data if present
    wd_raw = red.get(id + "_wallet_data")
    wallet_data = None
    if wd_raw:
        try:
            wallet_data = json.loads(wd_raw.decode())
        except Exception:
            wallet_data = {"raw": wd_raw.decode(errors="ignore")}
    response = {
        "status": status
    }
    if wallet_data is not None:
        response.update(wallet_data)
    # Keep data until TTL expiry (setex) so polling is stable and idempotent
    return response