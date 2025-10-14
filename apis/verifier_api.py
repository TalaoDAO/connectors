# apis/verifier_api.py
from flask import Blueprint
from flask_restx import Api, Namespace, Resource, fields

# Import the handler implemented in oidc4vp.py
# It reads JSON body (verifier_id, session_id, optional mode) and requires X-API-KEY,
# then returns {"url": "...", "report": "..."}.
from routes.verifier.oidc4vp import oidc4vp_qrcode  # Ensure PYTHONPATH finds oidc4vp.py

# Mount all verifier endpoints under /verifier
bp = Blueprint("verifier_app", __name__, url_prefix="/verifier")

# Bind RESTX to the blueprint; Swagger UI at /verifier/swagger
api = Api(
    bp,
    version="1.0",
    title="CONNECTORS Verifier API",
    description="OpenID endpoints for applications to bridge with the OIDC4VP Verifier.",
    doc="/swagger",
)

# Namespace => routes will be /verifier/app
ns = Namespace("app", description="OIDC4VP authorization request (QR Code) for customer applications")
api.add_namespace(ns, path="")

# ------------------------------------------------------------
# Models
# ------------------------------------------------------------
error_model = ns.model(
    "Error",
    {
        "error": fields.String(example="invalid_request"),
        "error_description": fields.String(example="missing verifier_id"),
    },
)

qrcode_request_model = ns.model(
    "OIDC4VPQRCodeRequest",
    {
        "verifier_id": fields.String(
            required=True,
            description="Identifier of the verifier/application (matches Verifier.application_api_issuer_id).",
            example="verifier-0000",
        ),
        "session_id": fields.String(
            required=True,
            description="Session identifier from the application; used for Redis correlation.",
            example="3f9b7c0e-7e69-4a2a-9d07-3d1d2a1c2c9e",
        ),
        "webhook_url": fields.String(
            required=False,
            description="Optional webhook URL, required if not saved in the configuration.",
            example="https://verifier.example.com/webhook",
        ),
        "mode": fields.String(
            required=False,
            description="Optional mode. Use 'audit' to trigger audit report generation, or 'test' for test flow.",
            enum=["audit", "test"],
            example="audit",
        ),
        "presentation": fields.Raw(
            required=False,
            description="Optional presentation object. Required if no presentation has been saved in the verifier configuration.",
            example={
                "id": "vp_def_1",
                "input_descriptors": [
                    {
                        "id": "age_over_18",
                        "constraints": {
                            "fields": [
                                {
                                    "path": ["$.age_over_18"],
                                }
                            ]
                        }
                    }
                ],
                "format": {"jwt_vp": {"alg": ["ES256", "RS256"]}}
            },
        ),
    },
)

qrcode_response_model = ns.model(
    "OIDC4VPQRCodeResponse",
    {
        "url": fields.String(
            required=True,
            description="Deep link / QR code URL for the wallet (contains request_uri).",
            example="openid-vc://?client_id=...&request_uri=https://example.com/verifier/wallet/request_uri/<stream_id>",
        ),
        "session_id": fields.String(
            required=True,
            description="User session identifier.",
            example="9555-6876-7686",
        )
    },
)

# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
@ns.route("")
class OIDC4VPQRCode(Resource):
    @ns.doc(
        description="Create an OIDC4VP Authorization Request (as a request_uri) to be displayed as a QR code.",
        params={
            "X-API-KEY": {
                "description": "API key header required by the server.",
                "in": "header",
                "required": True,
                "type": "string",
            }
        },
        responses={
            200: "OK",
            400: "Bad request",
            401: "Unauthorized",
        },
        consumes=["application/json"],
        produces=["application/json"],
    )
    @ns.expect(qrcode_request_model, validate=True)
    @ns.response(400, "Bad request", model=error_model)
    @ns.response(401, "Unauthorized", model=error_model)
    def post(self):
        """
        Build the OIDC4VP Authorization Request as a request_uri, returning a URL suitable for QR code display.
        """
        return oidc4vp_qrcode()

    
def init_app(app):
    app.register_blueprint(bp)
