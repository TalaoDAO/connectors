import os
import logging
from datetime import timedelta
from flask import Flask, redirect, request, render_template_string, current_app, Response, jsonify
from flask_session import Session
from flask_qrcode import QRcode
import redis
import markdown
import env
import json
import key_manager
from utils import message
from database import db
from db_model import seed_wallet, Wallet
from kms_model import seed_key
from routes import home, wallet, authorization_server, agent_chat, verifier, mcp_server, issuer

logging.basicConfig(level=logging.INFO)

# ---- default constants (overridable via env) ----
DEFAULT_API_LIFE = 5000
DEFAULT_GRANT_LIFE = 5000
DEFAULT_ACCEPTANCE_TOKEN_LIFE = 28 * 24 * 60 * 60

    
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
    
    # Redis init red = redis.StrictRedis()
    red = redis.Redis(host='localhost', port=6379, db=0)

    # ---- Security / secrets ----
    
    # ---- Sessions (server-side via Redis) ----
    
    app.config.update(
        SESSION_TYPE="redis",
        SESSION_REDIS=red,
        SESSION_PERMANENT=True,
        SESSION_COOKIE_NAME="connectors",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=int(os.getenv("SESSION_MINUTES", "30"))),
    )

    # ---- App metadata / UI helpers ----
    app.jinja_env.globals["Version"] = os.getenv("APP_VERSION", "0.4.1")
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
    app.config["REDIS"] = red
    app.config["API_LIFE"] = DEFAULT_API_LIFE
    app.config["GRANT_LIFE"] = DEFAULT_GRANT_LIFE
    app.config["ACCEPTANCE_TOKEN_LIFE"] = DEFAULT_ACCEPTANCE_TOKEN_LIFE
    app.config["SECRET_KEY"] = mode.secret_key
    # Agntcy 
    app.config["AGNTCY_ORG_API_KEY"] = mode.agntcy_org_api_key
    app.config["AGNTCY_AGENTIC_SERVICE_API_KEY"] = mode.agntcy_service_api_key
    with open("AGNTCY_SERVER_BADGES_JSON.json", "r") as f:
        app.config["AGNTCY_SERVER_BADGES_JSON"] = json.load(f)
    app.config["AGNTCY_IDENTITY_REST_BASE_URL"] =  "https://api.agent-identity.outshift.com"
    
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

    with app.app_context():
        db.create_all()
        # NOTE: seeding in production can be dangerous; guard by env flag
        if os.getenv("SEED_DATA", "1") == "1":
            logging.info("Run seed DB")
            seed_wallet(mode, manager)
            seed_key(myenv)
         
  

    # ---- Register routes / APIs ----
    verifier.init_app(app)    # your verifier API
    issuer.init_app(app)
    mcp_server.init_app(app)
    home.init_app(app)    
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
    
    #@app.errorhandler(404)
    #def page_not_found(e):
    #    return jsonify("Page not found")

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
    
    # .well-known for demo agent card
    @app.get("/.well-known/agent-card.json")
    @app.get("/.well-known/agent.json")
    def agent_card():
        card = {
            "name": "Wallet4Agent Demo Chat ",
            "description": "Chat with an Ai Agent equipped with a wallet and a DID.",
            "version": "1.0.0",
            "url":  mode.server + "a2a",
            "capabilities": {
                "streaming": False,
            },
            "defaultInputModes": ["text"],
            "defaultOutputModes": ["text"],
            "skills": [
                {
                "id": "1",
                "name": "Wallet4Agent Overview",
                "description": "Provide an overview of the Wallet4Agent features."
                }
            ],
            "provider": {
                "organization": "Web3 Digital Wallet"
            }
        }
        return jsonify(card)
    
    # .well-known for tesng with local agent
    @app.get("/local/.well-known/agent-card.json")
    def locl_agent_card():
        card = {
            "name": "Local Agent ",
            "description": "Just a test.",
            "version": "1.0.0",
            "url":  mode.server + "a2a",
            "capabilities": {
                "streaming": False,
            },
            "defaultInputModes": ["text"],
            "defaultOutputModes": ["text"],
            "skills": [
                {
                "id": "1",
                "name": "Wallet4Agent Overview",
                "description": "Provide an overview of the Wallet4Agent features."
                }
            ],
            "OIDC4VCWalletService": mode.server + "wallets/local",
            "provider": {
                "organization": "Web3 Digital Wallet"
            }
        }
        return jsonify(card)
        

    # .well-known DID API to serve DID Document as did:web
    @app.get('/<optional_path>/did.json')
    def well_known_did(optional_path):
        agent_identifier = "did:web:wallet4agent.com:" + optional_path
        this_wallet = Wallet.query.filter(Wallet.agent_identifier == agent_identifier).first()
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
    
    # service endpoint for linked vp
    @app.get('/service/<agent_identifier>/<id>')
    def service(agent_identifier, id):
        this_wallet = Wallet.query.filter(Wallet.agent_identifier == agent_identifier).first()
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
