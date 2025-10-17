from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timezone
from jwcrypto import jwk 
import json
from utils.kms import encrypt_json
from utils import oidc4vc
from sqlalchemy import CheckConstraint, Enum, UniqueConstraint, Index

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150))
    registration = db.Column(db.String(256)) # wallet/google/...
    given_name = db.Column(db.String(256))
    family_name = db.Column(db.String(256))
    login = db.Column(db.String(256),  unique=True)
    name = db.Column(db.String(256),  unique=True)
    subscription = db.Column(db.String(256)) # free/....
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime)
    usage_quota = db.Column(db.Integer, default=1000)
    organization = db.Column(db.String(256))
    billing_id = db.Column(db.String(128))
    country = db.Column(db.String(64))
    verifiers = db.relationship("Verifier", backref="user", lazy=True)
    signinss = db.relationship("Signin", backref="user", lazy=True)
    role = db.Column(db.String(64), default="user")
    profile_picture = db.Column(db.String(256), default ="default_picture.jpeg")  # stores filename or URL
    qtsp_account_username = db.Column(db.String(256))
    qtsp_account_password = db.Column(db.String(256))
    qtsp_account_access_identifier = db.Column(db.String(256))
    qtsp_account_access_key = db.Column(db.String(256))
    qtsp_account_tenant_id = db.Column(db.String(256))
    qtsp_account_app_name = db.Column(db.String(256))
    
    def qtsp_account(self):
        return {
            "password": self.qtsp_account_password,
            "username": self.qtsp_account_username,
            "access_identifier": self.qtsp_account_access_identifier,
            "access_key": self.qtsp_account_access_key,
            "tenant_id": self.qtsp_account_tenant_id,
            "app_name": self.qtsp_account_app_name,
        }


# Flask-Login user loader
def load_user(user_id):
    return User.query.get(int(user_id))


def default_verifier_encryption_key():
    key = jwk.JWK.generate(kty='EC', crv='P-256', alg='ES256')
    # Set additional parameters manually
    key_dict = json.loads(key.export(private_key=True))
    key_dict["alg"] = "ECDH-ES"
    key_dict["use"] = "enc"
    #key_dict["kid"] = "ac"
    return key_dict


def default_verifier_request_key():
    key = jwk.JWK.generate(kty="EC", crv="P-256", alg="ES256")
    return json.loads(key.export(private_key=True))


class Verifier(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(128), nullable=False, unique=True)
    description = db.Column(db.Text)
    verifier_type = db.Column(Enum("sandbox", "qualified", name="verifier_type"))
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=datetime.now, onupdate=datetime.now, nullable=False)
    client_id_scheme = db.Column(db.String(64), default="redirect_uri", nullable=False)
    client_id = db.Column(db.String(256))
    presentation_format = db.Column(Enum("presentation_exchange", "dcql_query", name="presentation_format"), default="presentation_exchange")
    presentation = db.Column(db.Text, default="{}")
    response_mode = db.Column(Enum("direct_post", "direct_post.jwt", name="response_mode", default="direct_post"))
    response_type =  db.Column(db.String(64), default="vp_token", nullable=False)
    credential_id = db.Column(db.String(256))
    credential_id_for_encryption = db.Column(db.String(256))
    verifier_info = db.Column(db.Text, default="{}")
    verifier_metadata = db.Column(db.Text, default="{}")
    application_api = db.Column(db.Text, nullable=False)
    application_api_verifier_id = db.Column(db.String(64), nullable=False, index=True)
    response_encryption = db.Column(db.Boolean, default=False, nullable=False)
    draft = db.Column(db.String(64), default="20", nullable=False)
    prefix = db.Column(db.String(64), default="openid4vp://", nullable=False)
    response_redirect_uri = db.Column(db.String(256))
    log = db.Column(db.Boolean, default=False, nullable=False)
    test = db.Column(db.String(256), default="")
    dc_api = db.Column(db.Boolean, default=False, nullable=False)
    webhook_url = db.Column(db.String(256), default="")
    webhook_api_key = db.Column(db.String(256), default="")



class Signin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(128), nullable=False, unique=True)
    description = db.Column(db.Text)
    signin_type = db.Column(Enum("sandbox", "qualified", name="signin_type"))
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.now, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=datetime.now, onupdate=datetime.now, nullable=False)
    client_id_scheme = db.Column(db.String(64), default="redirect_uri", nullable=False)
    client_id = db.Column(db.String(256))
    presentation_format = db.Column(Enum("presentation_exchange", "dcql_query", name="presentation_format"), default="presentation_exchange")
    landing_page = db.Column(db.String(256), default="google_style", nullable=False)
    response_mode = db.Column(Enum("direct_post", "direct_post.jwt", name="response_mode", default="direct_post"))
    credential_id = db.Column(db.String(256))
    credential_id_for_encryption = db.Column(db.String(256))
    signin_info = db.Column(db.Text, default="{}")
    signin_metadata = db.Column(db.Text, default="{}")
    application_api = db.Column(db.Text, nullable=False)
    application_api_client_id = db.Column(db.String(64), nullable=False, index=True)
    response_encryption = db.Column(db.Boolean, default=False, nullable=False)
    draft = db.Column(db.String(64), default="20", nullable=False)
    prefix = db.Column(db.String(64), default="openid4vp://", nullable=False)
    log = db.Column(db.Boolean, default=False, nullable=False)
    test = db.Column(db.String(256), default="")
    dc_api = db.Column(db.Boolean, default=False, nullable=False)


class Issuer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    application_api = db.Column(db.Text, unique=True)
    application_api_issuer_id = db.Column(db.Text, unique=True)
    name = db.Column(db.String(256), nullable=False)
    webhook_url = db.Column(db.String(256), nullable=False)
    issuer_urn = db.Column(db.String(64))
    issuer_type = db.Column(db.String(64))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime(timezone=True), default=datetime.now, onupdate=datetime.now, nullable=False)
    credential_id = db.Column(db.Text)
    draft = db.Column(db.String(64), default="13")
    prefix = db.Column(db.String(64), default="openid-credential-offer://")
    grant_type = db.Column(db.String(64))
    tx_code_required = db.Column(db.Boolean, default=False, nullable=False)
    tx_code_input_mode = db.Column(db.String(64), default="numeric")
    tx_code_length = db.Column(db.String(64))
    tx_code_description = db.Column(db.String(128))
    authorization_server = db.Column(db.String(256))
    par = db.Column(db.Boolean, default=False)
    log = db.Column(db.Boolean, default=False)
    sign_with_certificate = db.Column(db.Boolean, default=True)
    signed_metadata = db.Column(db.Boolean, default=False)
    credential_offer_uri = db.Column(db.Boolean, default=False)
    test = db.Column(db.String(256), default="")
    dc_api = db.Column(db.Boolean, default=False, nullable=False)
    issuer_metadata = db.Column(db.Text)
    status_list = db.Column(db.Boolean, default=True)
    vc_type = db.Column(db.Text)


class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)   # internal identifier
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    credential_id = db.Column(db.Text, unique=True)
    credential_type = db.Column(Enum("sandbox", "qualified", name="credential_type"), default="sandbox")
    use = db.Column(Enum("enc", "sign", name="use"), default="sign")
    description = db.Column(db.Text)
    key = db.Column(db.Text)  
    public_key = db.Column(db.Text, nullable=False)
    certificate = db.Column(db.Text)
    x5c = db.Column(db.Text) # trust chain
    did = db.Column(db.Text)
    verification_method = db.Column(db.Text)
    #verifier_attestation = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)
    provider = db.Column(db.String(64))
    san_dns = db.Column(db.String(64))
    san_uri = db.Column(db.String(256))
    exp = db.Column(db.DateTime)


def seed_credential():
    if not Credential.query.first():
        try:
            with open('keys.json') as f:
                keys = json.load(f)
            credentials = keys.get("credentials")
        except Exception:
            return
        for credential in credentials:
            default_key = Credential(
                user_id=1,
                credential_id=credential["credential_id"],
                credential_type=credential["credential_type"],
                use=credential["use"],
                description=credential["description"],
                provider=credential["provider"],
                key=encrypt_json(credential.get("key", {})),
                public_key=json.dumps(credential.get("public_key", {})),
                certificate=credential.get("certificate"),
                x5c=json.dumps(credential.get("x5c", [])),
                did=credential.get("did"),
                verification_method=credential.get("verification_method"),
                #verifier_attestation=credential.get("verifier_attestation"),
                san_dns=oidc4vc.extract_first_san_dns_from_der_b64(credential.get("certificate")),
                san_uri=oidc4vc.extract_first_san_uri_from_der_b64(credential.get("certificate")),
                exp=oidc4vc.extract_expiration(credential.get("certificate"))
            )
            db.session.add(default_key)
        db.session.commit()


def seed_signin_for_wallet_registration(mode):
    if not Signin.query.first():
        application_api = {
            "url": mode.server + "signin/app",
            "client_id": "0000",
            "client_secret": "0000"
        }
        default_signin = Signin(
            user_id=1,
            name="Wallet_onboarding",
            signin_type="sandbox",
            description="This is a signin for wallet onboarding",
            client_id_scheme="redirect_uri",
            client_id=mode.server + "signin/wallet/callback",
            landing_page="google_style",
            response_mode="direct_post",
            credential_id="signature_key_1",
            application_api=encrypt_json(application_api),
            application_api_client_id="0000",
            response_encryption=False,
            prefix="openid-vc://"
        )
        db.session.add(default_signin)
        db.session.commit()

verifier_metadata = {
    "vp_formats": {
        "vc+sd-jwt": {
            "kb-jwt_alg_values": [
                "ES256",
            ],
            "sd-jwt_alg_values": [
                "ES256",
            ]
        }
    }
}
def seed_verifier_for_demo(mode):
    if not Verifier.query.first():
        application_api_0 = {
            "url": mode.server + "verifier/app",
            "verifier_id": "0000",
            "verifier_secret": "0000"
        }
        verifier_0 = Verifier(
            user_id=1,
            name="Verifier for demon profile DIIP V3",
            draft="20",
            verifier_type="sandbox",
            description="This is a verifier for demo and swagger",
            client_id_scheme="redirect_uri",
            client_id=mode.server + "verifier/wallet/callback",
            response_mode="direct_post",
            credential_id="signature_key_1",
            webhook_url="http://example.com",
            application_api=encrypt_json(application_api_0),
            application_api_verifier_id="0000",
            response_encryption=False,
            prefix="openid-vc://",
            response_redirect_uri="",
            verifier_metadata=json.dumps(verifier_metadata)
        )
        application_api_1 = {
            "url": mode.server + "verifier/app",
            "verifier_id": "0001",
            "verifier_secret": "0001"
        }
        verifier_1 = Verifier(
            user_id=1,
            name="talao wallet draft 20",
            draft="20",
            verifier_type="sandbox",
            description="This is a verifier for demo mcp server",
            client_id_scheme="did",
            client_id=mode.server + "verifier/wallet/callback",
            response_mode="direct_post",
            credential_id="signature_key_1",
            webhook_url="http://example.com",
            application_api=encrypt_json(application_api_1),
            application_api_verifier_id="0001",
            response_encryption=False,
            prefix="openid-vc://",
            response_redirect_uri="",
            verifier_metadata=json.dumps(verifier_metadata)
        )
        application_api_2 = {
            "url": mode.server + "verifier/app",
            "verifier_id": "0002",
            "verifier_secret": "0002"
        }
        verifier_2 = Verifier(
            user_id=1,
            name="oidc4vp draft 28 (DIIP V4)",
            draft="28",
            verifier_type="sandbox",
            description="This is a verifier for demo mcp server",
            client_id_scheme="did",
            client_id=mode.server + "verifier/wallet/callback",
            response_mode="direct_post",
            credential_id="signature_key_1",
            webhook_url="http://example.com",
            application_api=encrypt_json(application_api_2),
            application_api_verifier_id="0002",
            response_encryption=False,
            prefix="openid-vc://",
            response_redirect_uri="",
            verifier_metadata=json.dumps(verifier_metadata)
        )
        db.session.add(verifier_0)
        db.session.add(verifier_1)
        db.session.add(verifier_2)
        db.session.commit()
            


def seed_user():
    if not User.query.first():
        
        default_user = User(
            email="contact@talao.io",
            created_at=datetime.now(timezone.utc),
            registration="initialisation",
            name="admin",
            role="admin",
            organization="Web3 Digital Wallet",
            country="FR",
            subscription="paid",
            profile_picture="default_picture.jpeg",
        )
        db.session.add(default_user)
        
        default_user = User(
            email="contact@talao.io",
            created_at=datetime.now(timezone.utc),
            registration="initialisation",
            name="test",
            organization="Web3 Digital Wallet",
            country="FR",
            subscription="free",
            role="user",
            profile_picture="default_picture.jpeg",
        )
        db.session.add(default_user)
        
        default_user = User(
            email="contact@talao.io",
            created_at=datetime.now(timezone.utc),
            registration="initialisation",
            name="test_paid",
            role="user",
            organization="Web3 Digital Wallet",
            country="FR",
            subscription="paid",
            profile_picture="default_picture.jpeg",
        )
        db.session.add(default_user)
        
        db.session.commit()
