from flask import redirect, request, current_app, flash, jsonify, render_template
from oauthlib.oauth2 import WebApplicationClient
import requests
import json
from flask_login import login_required, login_user
from db_model import Verifier, db, Issuer, Signin
from utils.kms import encrypt_json, decrypt_json
import uuid
import base64
import logging

logging.basicConfig(level=logging.INFO)


"""
TALAO_CLIENT_ID = "zbnfxaeeck"
TALAO_CLIENT_SECRET = "7a4caeed-7056-11f0-b19b-0a1628958560"
TALAO_DISCOVERY_URL = "https://talao.co/sandbox/verifier/app/.well-known/openid-configuration"
TALAO_CALLBACK = "https://8c7032575c41.ngrok.app/register/auth/talao/callback"

"""


def init_app(app):
    #app.add_url_rule('/verifier/online-test/<verifier_id>',  view_func=verifier_online_test, methods=['GET', 'POST'])
    
    # Audit Verifier
    app.add_url_rule('/verifier/online-test/audit/<verifier_type>/<id>',  view_func=verifier_online_test_audit, methods=['GET', 'POST'])
    # Test Verifier
    app.add_url_rule('/verifier/online-test/test/<verifier_type>/<id>',  view_func=verifier_online_test_test, methods=['GET', 'POST'])
    app.add_url_rule('/verifier/online-test/test/webhook',  view_func=verifier_online_test_webhook, methods=['GET', 'POST'])

    #app.add_url_rule('/signin/online-test/<signin_id>',  view_func=signin_online_test, methods=['GET', 'POST'])
    
    # Audit Sign-In
    app.add_url_rule('/signin/online-test/audit/<signin_type>/<id>',  view_func=signin_online_test_audit, methods=['GET', 'POST'])
    
    # Test Sign In
    app.add_url_rule('/signin/online-test/test/<signin_type>/<id>',  view_func=signin_online_test_test, methods=['GET', 'POST'])
    app.add_url_rule('/signin/online-test/<id>/callback',  view_func=signin_online_test_callback, methods=['GET', 'POST'])

    app.add_url_rule('/issuer/online/audit/<issuer_type>/<id>',  view_func=issuer_online_audit, methods=['GET', 'POST'])
    app.add_url_rule('/issuer/online/inspect/<issuer_type>/<id>',  view_func=issuer_online_inspect, methods=['GET', 'POST'])



# Audit Verifier
@login_required  
def verifier_online_test_audit(verifier_type, id):
    verifier = Verifier.query.get_or_404(id)
    mode = current_app.config["MODE"]

    api = decrypt_json(verifier.application_api)
    headers = {
        "content-Type": "Application/json",
        "X-API-KEY": api["verifier_secret"]
    }
    session_id = str(uuid.uuid1())
    data = {
        "verifier_id": api["verifier_id"],
        "session_id": session_id,
        "mode": "audit",
    }
    try:
        r = requests.post(f"{mode.server}verifier/app", headers=headers, json=data, timeout=5)
        r.raise_for_status()
        url = (r.json() or {}).get("url", "")
    except Exception:
        logging.warning("QR code value fetch failed = %s", r.json())
        return jsonify(r.json())
    try:
        report = get_report(verifier.draft, None,  url)
    except Exception as e:
        logging.error("Report failed %s", str(e))
        report = None
    return render_template(
            "audit.html",
            url=url,
            report=report,
            session_id=session_id,
            verifier_type=verifier.verifier_type,
            verifier_id=verifier.id)


# Test Verifier
@login_required
def verifier_online_test_test(verifier_type, id):
    verifier = Verifier.query.get_or_404(id)
    mode = current_app.config["MODE"]

    api = decrypt_json(verifier.application_api)
    headers = {
        "content-Type": "Application/json",
        "X-API-KEY": api["verifier_secret"]
    }
    session_id = str(uuid.uuid1())
    data = {
        "verifier_id": api["verifier_id"],
        "session_id": session_id,
        "mode": "test",
        "webhook_url": mode.server + 'verifier/online-test/test/webhook'
    }
    try:
        r = requests.post(f"{mode.server}verifier/app", headers=headers, json=data, timeout=5)
        r.raise_for_status()
        url = (r.json() or {}).get("url", "")
    except Exception:
        return jsonify(r.json())
    return render_template(
            "verifier/verifier_test.html",
            url=url,
            session_id=session_id,
            verifier_type=verifier.verifier_type,
            verifier_id=verifier.id)


def verifier_online_test_webhook():
    return jsonify('ok')


# Audit Sign-In
@login_required  
def signin_online_test_audit(signin_type, id):
    signin = Signin.query.get_or_404(id)
    if not signin.credential_id:
        flash("❌ Update the signin to select a credential ID")
        return redirect("/signin/select/" + signin_type)
    mode = current_app.config["MODE"]
    application_api = decrypt_json(signin.application_api)
    TALAO_CLIENT_ID = application_api["client_id"]
    TALAO_DISCOVERY_URL = application_api["url"] + "/.well-known/openid-configuration"
    TALAO_CALLBACK = mode.server + "signin/online-test/" + signin_id + "/callback"
    talao_config = requests.get(TALAO_DISCOVERY_URL).json() 
    talao_client = WebApplicationClient(TALAO_CLIENT_ID)
    auth_uri = talao_client.prepare_request_uri(
        talao_config["authorization_endpoint"],
        redirect_uri=TALAO_CALLBACK,
        scope=["openid", "profile"],
        mode="audit"
    )
    return redirect(auth_uri)


# Test Sign-In
@login_required
def signin_online_test_test(signin_type, id):
    signin = Signin.query.get_or_404(id)
    if not signin.credential_id:
        flash("❌ Update the signin to select a credential ID")
        return redirect("/signin/select/" + signin_type)
    mode = current_app.config["MODE"]
    application_api = decrypt_json(signin.application_api)
    TALAO_CLIENT_ID = application_api["client_id"]
    TALAO_DISCOVERY_URL = application_api["url"] + "/.well-known/openid-configuration"
    TALAO_CALLBACK = mode.server + "signin/online-test/" + id + "/callback"
    talao_config = requests.get(TALAO_DISCOVERY_URL).json() 
    talao_client = WebApplicationClient(TALAO_CLIENT_ID)
    auth_uri = talao_client.prepare_request_uri(
        talao_config["authorization_endpoint"],
        redirect_uri=TALAO_CALLBACK,
        scope=["openid", "profile"],
        mode="test"
    )
    return redirect(auth_uri)


@login_required
def signin_online_test_callback(id):
    mode = current_app.config["MODE"]
    signin = Signin.query.get_or_404(id)
    application_api = decrypt_json(signin.application_api)
    TALAO_CLIENT_ID = application_api["client_id"]
    TALAO_DISCOVERY_URL = application_api["url"] + "/.well-known/openid-configuration"
    TALAO_CLIENT_SECRET = application_api["client_secret"]
    TALAO_CALLBACK = mode.server + "signin/online-test/" + id + "/callback"
    talao_config = requests.get(TALAO_DISCOVERY_URL).json()
    talao_client = WebApplicationClient(TALAO_CLIENT_ID)
    token_url, headers, body = talao_client.prepare_token_request(
        talao_config["token_endpoint"],
        authorization_response=request.url,
        redirect_url=TALAO_CALLBACK,
    )
    token_response = requests.post(token_url, headers=headers, data=body, auth=(TALAO_CLIENT_ID, TALAO_CLIENT_SECRET))
    talao_client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = talao_config["userinfo_endpoint"]
    uri, headers, body = talao_client.add_token(userinfo_endpoint)
    userinfo = requests.get(uri, headers=headers, data=body).json()
    return redirect("/signin/select/" + signin.signin_type)


# Audit Issuer
def issuer_online_audit(issuer_type, id):
    mode = current_app.config["MODE"]
    issuer = Issuer.query.get_or_404(id)
    application_api_json = decrypt_json(issuer.application_api)
    issuer_secret = application_api_json["issuer_secret"]
    issuer_id = application_api_json["issuer_id"]
    api_endpoint =  application_api_json["url"]

    vc = {
        "given_name": "John",
        "family_name": "DOE"
    }
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': issuer_secret
    }
    data = { 
        "issuer_id": issuer_id,
        "vc": {"VC_test": vc}, 
        "format": "dc+sd_jwt",
        "issuer_state": str(uuid.uuid1()),
        "credential_configuration_ids": ["VC_test"],
        "webhook": mode.server + "/issuer/online-test/" + id + "/webhook",
        "redirect": mode.server + "/issuer/online-test/" + id + "/redirect",
        "mode": "audit"
    }
    resp = requests.post(api_endpoint, headers=headers, json = data)
   
    try:
        redirect_uri = resp.json()['redirect_uri']
        qrcode_value = resp.json()['qrcode_value']
    except Exception:
        return jsonify("No qr code")
    try:
        report = get_report(None, issuer.draft, qrcode_value)
    except Exception as e:
        logging.error("Report failed %s", str(e))
        return jsonify("No qr code")
    return render_template(
            "audit.html",
            url=qrcode_value,
            report=report,
            session_id="session_id",
            verifier_type="sandbox",
            verifier_id=issuer.id)



def issuer_online_inspect(issuer_type, id):
    return render_template(
            "issuer/issuer_inspect.html",
            issuer_type=issuer_type,
            issuer_id=id
    )



def get_report(oidc4vpdraft, oidc4vcidraft, url):
    mode = current_app.config["MODE"]
    if mode.myenv == "aws":
        api_url = "https://talao.co/api/anlyse-qrcode"
    else:
        api_url = "http://" + mode.IP + ":3000/api/analyze-qrcode"
    
    headers = {
        "Content-Type": "application/json",
        "Api-Key": "your-api-key", #TODO
    }
    payload = {
        "qrcode": base64.b64encode(url.encode()).decode(),
        "oidc4vpDraft":  oidc4vpdraft,
        "oidc4vciDraft": oidc4vcidraft,
        "profile": "connectors",
        "format": "text",
        "model": "flash" # "escalation",
    }
    try:
        resp = requests.post(api_url, json=payload, headers=headers, timeout=300)
        resp.raise_for_status()
        # If the API returns JSON:
    except requests.HTTPError as e:
        logging.warning("HTTP error: %s and %s", e.response.status_code, e.response.text)
    except requests.RequestException as e:
        logging.warning("Request failed: %s", e)    
    return base64.b64decode(resp.json()["report_base64"].encode()).decode()