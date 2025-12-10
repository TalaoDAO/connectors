import os
import logging
from datetime import timedelta
from flask import Flask, redirect, request, render_template_string, current_app, Response, jsonify
from flask_session import Session
from flask_qrcode import QRcode
from flask_login import LoginManager
import redis
import markdown
import env
import json
from db_model import Wallet
import key_manager
import linked_vp
from utils import oidc4vc
import copy


# Your modules
from utils import message
from database import db
from db_model import load_user, seed_user, seed_wallet

from kms_model import seed_key

# Routes / APIs (kept as they are, just registered here)
from routes import home, register, wallet, authorization_server,agent_chat


from routes import verifier  
from routes.status_list import statuslist
from apis import mcp_server


# ---- default constants (overridable via env) ----
DEFAULT_API_LIFE = 5000
DEFAULT_GRANT_LIFE = 5000
DEFAULT_ACCEPTANCE_TOKEN_LIFE = 28 * 24 * 60 * 60

def _adapt_oasf_for_wallet(oasf_template: dict, wallet: Wallet) -> dict:
    """
    Take the base OASF.json template and adapt it for a specific wallet:
    - Set the OASF `id` to the Agent DID.
    - Filter agent tools according to wallet flags (sign, receive_credentials, publish_unpublish).
    - Expose capabilities under wallet4agent.capabilities.
    """
    oasf = copy.deepcopy(oasf_template)

    agent_did = wallet.did
    # Subject of the OASF: this Agent's DID
    oasf["id"] = agent_did

    # ---- Expose capabilities in wallet4agent section ----
    w4a = oasf.get("wallet4agent") or {}
    capabilities = w4a.get("capabilities") or {}

    capabilities.update(
        {
            "sign": bool(wallet.sign),
            "receive_credentials": bool(wallet.receive_credentials),
            "publish_unpublish": bool(wallet.publish_unpublish),
            "always_human_in_the_loop": bool(wallet.always_human_in_the_loop),
        }
    )

    w4a["capabilities"] = capabilities
    oasf["wallet4agent"] = w4a

    # ---- Adapt tools inside the mcp_server module ----
    modules = oasf.get("modules") or []
    for module in modules:
        if module.get("type") != "mcp_server":
            continue

        tools = module.get("tools") or []
        filtered_tools = []

        for tool in tools:
            name = tool.get("name")
            if not name:
                filtered_tools.append(tool)
                continue

            # In the new OASF.json, tools use "role" (guest/agent/dev).
            role = tool.get("role") or tool.get("audience") or "agent"

            # Guests & dev tools are always present
            if role in ("guest", "admin"):
                filtered_tools.append(tool)
                continue

            if role != "agent":
                # Any other audience: keep as-is
                filtered_tools.append(tool)
                continue

            # ---- Agent tools: gate them by wallet flags ----

            # Receiving credentials
            if name == "accept_credential_offer" and not wallet.receive_credentials:
                # Agent cannot receive credentials
                continue

            # Signing tools
            if name in ("sign_text_message", "sign_json_payload") and not wallet.sign:
                # Agent cannot sign
                continue

            # Publish / unpublish tools
            if name in ("publish_attestation", "unpublish_attestation") and not wallet.publish_unpublish:
                # Agent is not allowed to manage Linked VP publication
                continue

            # All remaining agent tools are always available
            filtered_tools.append(tool)

        module["tools"] = filtered_tools

    return oasf


def create_oasf_vp(agent_identifier, manager, mode):
    this_wallet = Wallet.query.filter(Wallet.did == agent_identifier).one_or_none()
    if not this_wallet:
        return None

    with open("OASF.json", "r", encoding="utf-8") as f:
        oasf_template = json.load(f)

    # local copy of the same helper logic, or import from wallet_tools if you prefer
    oasf_json = _adapt_oasf_for_wallet(oasf_template, this_wallet)

    oasf_json["disclosure"] = ["all"]
    oasf_json["vct"] = "urn:ai-agent:oasf:0001"

    profile = this_wallet.ecosystem_profile
    if profile == "DIIP V3":
        draft = 13
    else:
        draft = 15

    cred = oidc4vc.sign_sdjwt_by_agent(oasf_json, agent_identifier, manager,draft=draft, duration=360 * 24 * 60 * 60,)

    success, message = linked_vp.store_and_publish( cred, agent_identifier, manager, mode, published=True,
        type="OASF")
    if success:
        return True

    logging.warning("Failed to publish OASF record as Linked VP %s", message)
    return False
 
    
def create_app() -> Flask:
    """Application factory: configure, wire dependencies, register routes/APIs."""
    # Base Flask app
    app = Flask(__name__)
    
    @app.get("/ping")
    def ping():
        return "pong"

    # ---- Logging (basic) ----
    # In production, prefer dictConfig with JSON or structured logs
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

    # ---- Environment / Mode ----
    # Environment variables are set in gunicornconf.py and used via utils.environment
    myenv = os.getenv("MYENV", "local")
    mode = env.currentMode(myenv)  # object with .server, .port, .flaskserver, etc.
    mode.debug_on()
    
    # Redis init red = redis.StrictRedis()
    red = redis.Redis(host='localhost', port=6379, db=0)

    # ---- Security / secrets ----
    # NEVER hardcode secrets; load from env or secret manager
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me-in-prod")

    # ---- Sessions (server-side via Redis) ----
    app.config.update(
        SESSION_PERMANENT=True,
        SESSION_COOKIE_NAME="connectors",
        SESSION_TYPE="redis",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=int(os.getenv("SESSION_MINUTES", "30"))),
        SESSION_FILE_THRESHOLD=100,  # unused with redis, but OK to leave
    )

    # ---- App metadata / UI helpers ----
    app.jinja_env.globals["Version"] = os.getenv("APP_VERSION", "0.2")
    try:
        app.jinja_env.globals["Created"] = os.path.getctime(__file__)
    except Exception:
        app.jinja_env.globals["Created"] = ""


    # Default / primary DB
    main_db = os.getenv("SQLALCHEMY_DATABASE_URI") or (
        "sqlite:///" + os.path.abspath("data/connectors.db")
    )

    # Local KMS DB 
    local_kms_db = os.getenv("SQLALCHEMY_SECOND_DATABASE_URI") or (
        "sqlite:///" + os.path.abspath("data/local_kms.db")
    )

    # Primary DB URI (used for models without __bind_key__)
    app.config["SQLALCHEMY_DATABASE_URI"] = main_db

    # Additional binds
    app.config["SQLALCHEMY_BINDS"] = {
        "second": local_kms_db,   # "second" is the bind key name
    }

    # ---- App-wide config values (shared deps) ----
    app.config["MYENV"] = myenv
    app.config["MODE"] = mode
    app.config["SESSION_TYPE"] = "redis"
    app.config["SESSION_REDIS"] = red
    app.config["REDIS"] = red
    app.config["API_LIFE"] = int(os.getenv("API_LIFE", DEFAULT_API_LIFE))
    app.config["GRANT_LIFE"] = int(os.getenv("GRANT_LIFE", DEFAULT_GRANT_LIFE))
    app.config["ACCEPTANCE_TOKEN_LIFE"] = int(os.getenv("ACCEPTANCE_TOKEN_LIFE", DEFAULT_ACCEPTANCE_TOKEN_LIFE))
    
   
    # OAUTHLIB_INSECURE_TRANSPORT is only for local/dev; do not enable in prod
    if myenv == "local":
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    
 
    # initialize KMS
    manager = key_manager.kms_init(myenv)
    app.config["MANAGER"] = manager

    # ---- Init extensions bound to app ----
    db.init_app(app)
    Session(app)
    QRcode(app)

    # ---- DB bootstrap / seed (idempotent) ----
    agent_list = ["did:web:wallet4agent.com:demo", "did:web:wallet4agent.com:demo2", "did:web:wallet4agent.com:diipv4", "did:web:wallet4agent.com:ewc",
    "did:web:wallet4agent.com:arf" ]
    if myenv == "local":
        agent_list.append("did:cheqd:testnet:209779d5-708b-430d-bb16-fba6407cd1ac")
    else:
        agent_list.append("did:cheqd:testnet:209779d5-708b-430d-bb16-fba6407cd1aa")
        
    with app.app_context():
        db.create_all()
        # NOTE: seeding in production can be dangerous; guard by env flag
        if os.getenv("SEED_DATA", "1") == "1":
            logging.info("Run seed DB")
            seed_user()
            seed_wallet(mode, manager)
            seed_key()
            for agent in agent_list:
                create_oasf_vp(agent, manager, mode)

    # ---- Flask-Login ----
    login_manager = LoginManager()
    login_manager.login_view = "register"   # endpoint name for redirect
    login_manager.init_app(app)
    login_manager.user_loader(load_user)

    # ---- Register routes / APIs ----
    verifier.init_app(app)    # your verifier API
    
    mcp_server.init_app(app)
    
    home.init_app(app)
    register.init_app(app, db)

    statuslist.init_app(app)
    
    wallet.init_app(app)
    authorization_server.init_app(app)
    agent_chat.init_app(app)
    
    
    # ---- Error handlers ----
    @app.errorhandler(403)
    def page_abort(e):
        logging.warning("403 Forbidden: %s", e)
        return redirect(mode.server + "login/")

    @app.errorhandler(500)
    def error_500(e):
        try:
            message.message("Error 500 on connectors", "thierry.thevenet@talao.io", str(e), mode)
        except Exception as x:
            logging.warning("message() failed: %s", x)
        return redirect(mode.server + "/")
    
    @app.errorhandler(404)
    def page_not_found(e):
        return jsonify("Page not found")


    # ---- Helpers attached to app context ----
    def front_publish(stream_id: str, error: str, error_description: str) -> None:
        """Publish an event on Redis pub/sub for the front channel."""
        payload = {"stream_id": stream_id}
        if error:
            payload["error"] = error
        if error_description:
            payload["error_description"] = error_description
        # Use the configured Redis instance
        current_app.config["REDIS"].publish("issuer_oidc", json.dumps(payload).encode("utf-8"))

    # make helper available if yo
    app.extensions = getattr(app, "extensions", {})
    app.extensions["front_publish"] = front_publish

    # ---- Minimal safe markdown file endpoint ----
    @app.get("/md_file")
    def md_file():
        """
        Render a whitelisted markdown file as HTML. Prevents path traversal.
        """
        allowed = {
            "privacy": "privacy_en.md",
            "terms_and_conditions": "mobile_cgu_en.md",
        }
        key = request.args.get("file", "")
        fname = allowed.get(key)
        if not fname:
            return redirect(mode.server + "login/")

        try:
            with open(fname, "r", encoding="utf-8") as f:
                content = f.read()
        except FileNotFoundError:
            return "File not found", 404

        html = markdown.markdown(content, extensions=["fenced_code"])
        return render_template_string(html)


    # .well-known DID API to serve DID Document as did:web
    @app.get('/<optional_path>/did.json')
    def well_known_did(optional_path):
        wallet_did = "did:web:wallet4agent.com:" + optional_path
        this_wallet = Wallet.query.filter(Wallet.did == wallet_did).one_or_none()
        headers = {
            "Content-Type": "application/did+ld+json",
            "Cache-Control": "no-cache",
            "Access-Control-Allow-Origin": "*"
        }
        
        if not this_wallet:
            resp = {"error": "notFound"}
            headers_error = {
                "Content-Type": "application/json",
                "Cache-Control": "no-cache",
                "Access-Control-Allow-Origin": "*",
            }
            return Response(json.dumps(resp), headers=headers_error, status=404)
        
        did_doc = this_wallet.did_document
        return Response(did_doc, headers=headers)
    
    
    @app.get('/service/<wallet_did>/<id>')
    def service(wallet_did, id):
        this_wallet = Wallet.query.filter(Wallet.did == wallet_did).one_or_none()
        service = json.loads(this_wallet.linked_vp).get(id)
        if service:
            headers = {
                "Content-Type": "application/json",
                "Cache-Control": "no-cache"
            }
            return Response(json.dumps(service), headers=headers)
        else:
            return jsonify({"error": "linked VP Not found"}), 401
    
    return app



# ---- Dev entrypoint: `python app.py` ----
if __name__ == "__main__":
    app = create_app()
    mode = app.config["MODE"]
    logging.info("Starting Flask dev server at %s:%s (env: %s)", mode.IP, mode.port, os.getenv("MYENV", "local"))
    app.run(host=mode.IP, port=mode.port, debug=os.getenv("FLASK_DEBUG", "1") == "1", threaded=True)
