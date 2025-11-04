from flask import redirect, request, render_template, current_app, flash, session, url_for
from oauthlib.oauth2 import WebApplicationClient
import requests
import json
from flask_login import login_required, login_user, logout_user
from db_model import User, db, Signin, Wallet
import logging
from requests.exceptions import RequestException, HTTPError
from utils.kms import encrypt_json, decrypt_json
from utils import message

ngrok =  "https://c8e7a2920835.ngrok.app"

try:
    with open('keys.json') as f:
        keys = json.load(f)
except Exception:
    logging.error('Unable to load keys.json — file missing or corrupted.')
    sys.exit(1)

# OAuth clients (for Google & GitHub)
GOOGLE_CLIENT_ID = keys.get("google_client_id")
GOOGLE_CLIENT_SECRET = keys.get("google_client_secret")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
GOOGLE_CALLBACK = "https://wallet-connectors.com/register/auth/google/callback"

GITHUB_CLIENT_ID = keys.get("github_client_id")
GITHUB_CLIENT_SECRET = keys.get("github_client_secret")
GITHUB_CALLBACK = "https://wallet-connectors.com/register/auth/github/callback"


google_client = WebApplicationClient(GOOGLE_CLIENT_ID)
github_client = WebApplicationClient(GITHUB_CLIENT_ID)
#talao_client = WebApplicationClient(TALAO_CLIENT_ID)

ENTRY = "/verifier/select/sandbox"
ENTRY = "/menu"

def init_app(app, db):
    
    app.add_url_rule('/register',  view_func=register, methods=['GET'])

    app.add_url_rule('/register/auth/google',  view_func=login_with_google, methods=['POST', 'GET'])
    app.add_url_rule('/register/auth/google/callback', view_func=register_google_callback, methods=['GET', 'POST'], defaults={'db': db})
    app.add_url_rule('/register/auth/github',  view_func=login_with_github, methods=['GET', 'POST'])
    app.add_url_rule('/register/auth/github/callback',  view_func=register_github_callback, methods=['GET', 'POST'], defaults={'db': db})
    
    app.add_url_rule('/register/auth/wallet',  view_func=login_with_wallet, methods=['GET', 'POST'])
    app.add_url_rule('/register/auth/wallet/callback',  view_func=register_wallet_callback, methods=['GET', 'POST'], defaults={'db': db})
    
    app.add_url_rule('/register/test',  view_func=register_test, methods=['GET', 'POST'])
    app.add_url_rule('/register/admin',  view_func=register_admin, methods=['GET', 'POST'])
    
# entry pooint
def register():
    session_id = request.args.get("session_id", "")
    optional_path = request.args.get("optional_path")
    mode = current_app.config["MODE"]
    wallet = Wallet.query.filter(Wallet.optional_path == optional_path).one_or_none()
    if not wallet:
        message = "Wallet not found"
        return render_template("wallet/session_screen.html", message=message, title= "Access Denied")
    
    if wallet.owner_identity_provider == "google":
        return redirect(url_for("login_with_google", session_id=session_id))
    elif wallet.owner_identity_provider == "github":
        return redirect(url_for("login_with_github", session_id=session_id))
    elif wallet.owner_identity_provider == "wallet":
        return redirect(url_for("login_with_wallet", session_id=session_id))
    
    return render_template("register.html", mode=mode, title="Authenticate", session_id=session_id, optional_path=optional_path)


def login_with_google():
    google_config = requests.get(GOOGLE_DISCOVERY_URL).json()
    state = request.args.get("session_id")
    auth_uri = google_client.prepare_request_uri(
        google_config["authorization_endpoint"],
        redirect_uri=GOOGLE_CALLBACK,
        scope=["openid", "email", "profile"],
        state=state,
        prompt="select_account"  # forces account picker on next login
    )
    return redirect(auth_uri)

def register_google_callback(db):
    mode = current_app.config["MODE"]
    red = current_app.config["REDIS"]
    session_id = request.args.get("state")
    google_config = requests.get(GOOGLE_DISCOVERY_URL).json()
    token_url, headers, body = google_client.prepare_token_request(
        google_config["token_endpoint"],
        authorization_response=request.url,
        redirect_url=GOOGLE_CALLBACK
    )
    token_response = requests.post(token_url, headers=headers, data=body, auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET))
    google_client.parse_request_body_response(json.dumps(token_response.json()))
    userinfo_endpoint = google_config["userinfo_endpoint"]
    uri, headers, body = google_client.add_token(userinfo_endpoint)
    userinfo = requests.get(uri, headers=headers, data=body).json()
    user = User.query.filter_by(email=userinfo.get("email")).first()
    if user:
        session_config = json.loads(red.get("state").decode())
        if userinfo.get("email") == session_config["owner_login"]:
            logout_user()
            login_user(user)
            logging.info("owner is now authenticated")
            return redirect("/" + session_config["optional_path"] + "/credential_offer?session_id=" + session_id)
    return redirect("/")
    
    # not used
    new_user = User(
        email=userinfo["email"],
        given_name=userinfo["given_name"],
        family_name=userinfo["family_name"],
        name=userinfo["given_name"] + " " + userinfo["family_name"],
        registration="google",
        subscription="free"
    )
    db.session.add(new_user)
    db.session.commit()
    try:
        message.message("New user on Wallet Connectors", "thierry.thevenet@talao.io", json.dumps(userinfo), mode)
    except Exception as x:
        logging.warning("message() failed: %s", x)
    login_user(new_user)
    return redirect(ENTRY)



def login_with_github():
    state = request.args.get("session_id")
    return redirect(f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&redirect_uri={GITHUB_CALLBACK}&scope=user:email&state={state}")


def register_github_callback(db):
    mode = current_app.config["MODE"]
    red = current_app.config["REDIS"]
    code = request.args.get("code")
    session_id = request.args.get("state")

    token_resp = requests.post(
        "https://github.com/login/oauth/access_token",
        headers={"Accept": "application/json"},
        data={
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code
        }
    ).json()
    headers = {'Authorization': f'token {token_resp.get("access_token")}'}
    userinfo = requests.get("https://api.github.com/user", headers=headers).json()
    user = User.query.filter_by(login=userinfo.get("login")).first()
    if user:
        session_config = json.loads(red.get("state").decode())
        if userinfo.get("login") == session_config["owner_login"]:
            logout_user()
            login_user(user)
            logging.info("owner is now authenticated")
            return redirect("/" + session_config["optional_path"] + "/credential_offer?session_id=" + session_id)
    return redirect("/")
    
    new_user = User(
        login=userinfo["login"],
        registration="github",
        subscription="free",
        name=userinfo["login"]
    )
    db.session.add(new_user)
    db.session.commit()
    try:
        message.message("New user on Wallet Connectors", "thierry.thevenet@talao.io", json.dumps(userinfo), mode)
    except Exception as x:
        logging.warning("message() failed: %s", x)
    login_user(new_user)
    return redirect(ENTRY)


def login_with_wallet():
    state = request.args.get("session_id")
    mode = current_app.config["MODE"]
    signin = db.session.get(Signin, 1)
    application_api = decrypt_json(signin.application_api)
    
    TALAO_CLIENT_ID = application_api["client_id"]
    TALAO_DISCOVERY_URL = application_api["url"] + "/.well-known/openid-configuration"
    TALAO_CALLBACK = mode.server + "register/auth/wallet/callback"
    talao_client = WebApplicationClient(TALAO_CLIENT_ID)
    talao_config = requests.get(TALAO_DISCOVERY_URL).json()
    auth_uri = talao_client.prepare_request_uri(
        talao_config["authorization_endpoint"],
        redirect_uri=TALAO_CALLBACK,
        scope=["openid"],
        state=state
    )
    return redirect(auth_uri)


def register_wallet_callback(db):
    mode = current_app.config["MODE"]
    red = current_app.config["REDIS"]
    session_id = request.args.get("state")
    # Load verifier / client config from DB
    signin = db.session.get(Signin, 1)
    application_api = decrypt_json(signin.application_api)
    TALAO_CLIENT_ID = application_api["client_id"]
    TALAO_CLIENT_SECRET = application_api["client_secret"]
    TALAO_DISCOVERY_URL = application_api["url"].rstrip("/") + "/.well-known/openid-configuration"
    TALAO_CALLBACK = mode.server.rstrip("/") + "/register/auth/wallet/callback"
    talao_client = WebApplicationClient(TALAO_CLIENT_ID)

    # 1) Discover OIDC endpoints
    disc_resp = requests.get(TALAO_DISCOVERY_URL, timeout=10)
    talao_config = disc_resp.json()
    token_endpoint = talao_config["token_endpoint"]
    userinfo_endpoint = talao_config["userinfo_endpoint"]

    # 2) Build and send the token request
    token_url, headers, body = talao_client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=TALAO_CALLBACK,
    )
    token_resp = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(TALAO_CLIENT_ID, TALAO_CLIENT_SECRET),
        timeout=10,
    )
    logging.info("Token response text: %s", token_resp.text)
    token_resp.raise_for_status()

    # Parse token response into the OAuth client
    talao_client.parse_request_body_response(token_resp.text)

    # 3) Call the userinfo endpoint with the access token
    uri, headers, _ = talao_client.add_token(userinfo_endpoint)
    ui_resp = requests.get(uri, headers=headers, timeout=10)

    userinfo = ui_resp.json()
    logging.info("userinfo response = %s", json.dumps(userinfo, indent=2))

    sub = userinfo.get("sub")
    if not sub:
        flash("❌ Wallet verification failed: missing 'sub' in userinfo.")
        return redirect("/")

    user = User.query.filter_by(login=sub).first()
    print("user name = ", user.name)
    if user:
        session_config = json.loads(red.get(session_id).decode())
        print("session config = ", session_config["owner_login"])
        if sub == session_config["owner_login"]:
            logout_user()
            login_user(user)
            logging.info("owner is now authenticated")
            return redirect("/" + session_config["optional_path"] + "/credential_offer?session_id=" + session_id)
    return redirect("/")
  


def register_test():
    mode = current_app.config["MODE"]
    logout_user()
    user = User.query.filter_by(name="test").first()
    if mode.myenv == 'local':
        login_user(user)
    return redirect(ENTRY)


def register_admin():
    session_id = request.form.get("session_id", "")
    optional_path = request.form.get("optional_path")
    if session_id and optional_path:
        logout_user()
        # sign in user
        user = User.query.filter_by(name="admin").first()
        login_user(user)
        logging.info("user is now authenticated")
        return redirect("/" + optional_path + "/credential_offer?session_id=" + session_id)
    
    # standard registration
    else:
        mode = current_app.config["MODE"]
        logout_user()
        user = User.query.filter_by(name="admin").first()
        if mode.myenv == 'local':
            login_user(user)
        return redirect(ENTRY)