# apis/issuer_api.py
import uuid, json
import logging
import requests
from datetime import datetime, timedelta
from flask import jsonify, request, Response, current_app
from flask_restx import Api, Namespace, Resource, fields
from flask import Blueprint  
from db_model import Issuer, db
from utils.kms import encrypt_json, decrypt_json
from routes.issuer import build_issuer_metadata


API_LIFE = 5000
#ACCESS_TOKEN_LIFE = 1000
GRANT_LIFE = 5000
ACCEPTANCE_TOKEN_LIFE = 28 * 24 * 60 * 60

bp = Blueprint("issuer_api", __name__, url_prefix="/issuer")


api = Api(
    bp,
    version="1.0",
    title="CONNECTORS Issuer API",
    description="Endpoints for applications to bridge with the OIDC4VCI Issuer.",
    contact="contact@talao.io",
    authorizations={'apikey': {'type': 'apiKey', 'in': 'header', 'name': 'X-API-KEY'}},
    doc="/swagger",   # Swagger UI -> /issuer/swagger
)

# Namespace (kept as 'issuer'); path="" so @ns.route("/api") -> /issuer/api
ns = Namespace('app', description='Endpoints to get the QR code value or the URL to the QR code page')
api.add_namespace(ns, path="")


# Examples
_vc_example = {
    "given_name": "John",
    "family_name": "DOE"
}

# Models
payload = ns.model(
    'Payload input',
    {
        'issuer_id': fields.String(example="ooroomolyd", required=True),
        'vc': fields.Raw(example=_vc_example),
        'issuer_state': fields.String(example='state_1', required=True),
        'user_pin': fields.String("124567"),
    },
    description="API payload",
)
# --- models (add examples so Swagger shows Example Value) ---

error_model = ns.model(
    "Error",
    {
        "error": fields.String(example="invalid_request"),
        "error_description": fields.String(example="issuer_state missing"),
    }
)

success_model = ns.model(
    "IssuerResponse",
    {
        "qrcode_value": fields.String(
            description="Credential Offer / QR payload",
            example="openid-credential-offer://?credential_offer=eyJpc3N1ZXIiOi..."
        ),
    }
)

response = ns.model(
    'Response',
    {
        'qrcode_value': fields.String(description='API response', required=True)
    }
)


@ns.route("/credential-offer")
class CredentialOffer(Resource):
    @ns.response(200, "Success", model=success_model)
    @ns.response(400, "Invalid request", model=error_model)
    @ns.response(401, "Unauthorized", model=error_model)
    @ns.doc(security='apikey')
    @ns.expect(payload, validate=False)
    #@ns.marshal_with(success_model, code=200)  # marshal only the 200 response
    def post(self):
        """
        Returns a QR code value and a redirect URL for credential issuance.
        """
        mode = current_app.config["MODE"]
        red = current_app.config["REDIS"]

        # --- Auth ---
        api_key = request.headers.get("X-API-KEY")
        if not api_key:
            return {"error": "unauthorized", "error_description": "Missing X-API-KEY"}, 401

        # --- Payload ---
        body = request.get_json(silent=True) or {}
        issuer_id = body.get("issuer_id")
        if not issuer_id:
            return {"error": "invalid_request", "error_description": "issuer_id missing"}, 400
        issuer = Issuer.query.filter(Issuer.application_api_issuer_id == issuer_id).one_or_none()
        if not issuer:
            logging.warning("issuer_id not found: %s", issuer_id)
            return {"error": "unauthorized", "error_description": "Unknown issuer_id"}, 401

        # Decrypt stored API config and compare secret
        try:
            api_cfg = decrypt_json(issuer.application_api)
        except Exception:
            logging.exception("Issuer application_api decryption failed")
            return {"error": "server_error", "error_description": "Issuer configuration error"}, 500

        secret_expected = api_cfg.get("issuer_secret")  # FIX: correct key name
        if not secret_expected or api_key != secret_expected:
            logging.warning("X-API-KEY mismatch for issuer_id=%s", issuer_id)
            return {"error": "unauthorized", "error_description": "Unauthorized token"}, 401

        if not body.get("issuer_state"):
            return {"error": "invalid_request", "error_description": "issuer_state missing"}, 400
        
        # --- Build session data ---
        session_id = uuid.uuid4().hex
        
        if issuer.grant_type == "authorization_code":
            if body.get('vc'):
                return {"error": "invalid_request", "error_description": "no vc claim is needed in authorization_code flow"}, 400
            
            session_data = {
                "grant_type": "authorization_code",
                "session_id": session_id,
                "issuer_id": issuer_id,
                "credential_issuer":  f'{mode.server}issuer/{issuer_id}',
                "issuer_state": body.get("issuer_state"),
                "issuer_metadata": build_issuer_metadata.build_credential_issuer_metadata(issuer_id)
            }
            logging.info(json.dumps(session_data["issuer_metadata"], indent=4))
            
        else:  # pre authorized code flow
            if not body.get('vc'):
                return {"error": "invalid_request", "error_description": "vc claim is missing"}, 400
        
            vc_type_list = []
            for obj in json.loads(issuer.vc_type):
                credential_identifier = obj.get('credential_identifier')
                vc_type_list.append(credential_identifier)
            for vc in list(body.get('vc')):
                if vc not in vc_type_list:
                    logging.error("%s is not in the issuer metadata", vc)
                    return {"error": "invalid_request", "error_description": vc + " is not supported by the issuer"}, 400
            
            pre_authorized_code = uuid.uuid4().hex
            session_data = {
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "session_id": session_id,
                "vc": body.get("vc"),
                "pre-authorized_code": pre_authorized_code,
                "issuer_id": issuer_id,
                "credential_issuer":  f'{mode.server}issuer/{issuer_id}',
                "issuer_state": body.get("issuer_state"),
                "user_pin": body.get("user_pin"),
                "issuer_metadata": build_issuer_metadata.build_credential_issuer_metadata(issuer_id)
            }
            logging.info(json.dumps(session_data["issuer_metadata"], indent=4))
            red.setex(pre_authorized_code, API_LIFE, json.dumps(session_data))  # use for pre authorized code flow

        # Cache the session data session_id
        red.setex(session_id, API_LIFE, json.dumps(session_data)) # use for pre authorized code flow

        # --- Retrieve QRCode value from app route ---
        qrcode_value = ""
        try:
            r = requests.get(f"{mode.server}application/issuer/qrcode/{issuer_id}/{session_id}", timeout=5)
            r.raise_for_status()
            qrcode_value = (r.json() or {}).get("qrcode_value", "")
        except Exception:
            logging.exception("QR code value fetch failed for issuer_id=%s", issuer_id)

        return {"qrcode_value": qrcode_value}, 200


def init_app(app):
    """
    Register the issuer API blueprint on the Flask app.
    This avoids endpoint collisions with other RESTX Api instances.
    """
    app.register_blueprint(bp)
