from flask_login import UserMixin
from datetime import datetime, timezone
import json
from utils import oidc4vc
import logging
from database import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150))
    registration = db.Column(db.String(256)) # wallet/google/...
    given_name = db.Column(db.String(256))
    family_name = db.Column(db.String(256))
    login = db.Column(db.String(256),  unique=True)
    subscription = db.Column(db.String(256)) # free/....
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime)
    usage_quota = db.Column(db.Integer, default=1000)
    organization = db.Column(db.String(256))
    role = db.Column(db.String(64), default="admin")


# Flask-Login user loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)   # internal identifier
    admin_pat_jti = db.Column(db.String(64))
    agent_pat_jti = db.Column(db.String(64))
    client_secret_hash = db.Column(db.String(64))
    client_public_key = db.Column(db.Text)
    mcp_authentication = db.Column(db.String(256), default="Personal Access Token (PAT)")
    admins_identity_provider = db.Column(db.String(64))
    admins_login = db.Column(db.Text, default="[]")
    notification_email = db.Column(db.String(256))
    ecosystem_profile = db.Column(db.String(64), default="DIIP V3") # to comply with default Talao profile
    agent_framework = db.Column(db.String(64), default="None")
    url = db.Column(db.Text, unique=True)
    linked_vp = db.Column(db.Text, default="{}")
    chat_profile = db.Column(db.String(80), nullable=True)
    is_chat_agent = db.Column(db.Boolean, default=False)
    did = db.Column(db.Text, unique=True)
    did_document = db.Column(db.Text, default="{}")
    status = db.Column(db.String(256), default="pending")
    sign = db.Column(db.Boolean, default=True)
    always_human_in_the_loop = db.Column(db.Boolean, default=True)
    receive_credentials = db.Column(db.Boolean, default=True)
    publish_unpublish = db.Column(db.Boolean, default=True)
    agntcy_agent_badge = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    
class Attestation(db.Model):
    id = db.Column(db.Integer, primary_key=True)   # internal identifier
    wallet_did = db.Column(db.Text)
    service_id = db.Column(db.Text)
    name = db.Column(db.String(64))
    description = db.Column(db.Text)
    vc = db.Column(db.Text)
    issuer = db.Column(db.Text)
    vc_format = db.Column(db.String(64))
    vct = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.now)
    exp = db.Column(db.DateTime)
    published = db.Column(db.Boolean, default=False)


def seed_wallet(mode, manager, myenv):
    if not Wallet.query.first():
        vm = "did:web:wallet4agent.com:demo#key-1"
        key_id = manager.create_or_get_key_for_tenant(vm)
        jwk, kid, alg = manager.get_public_key_jwk(key_id)
        did_1 = "did:web:wallet4agent.com:demo"
        url = mode.server  + did_1
        admin_pat, admin_pat_jti = oidc4vc.generate_access_token(did_1, "admin", "pat", jti="demo")
        agent_pat, agent_pat_jti = oidc4vc.generate_access_token(did_1, "admin", "pat", jti="demo", duration=90*24*60*60)
        wallet_1 = Wallet(
            admin_pat_jti=admin_pat_jti,  # 365 days
            agent_pat_jti=agent_pat_jti,
            always_human_in_the_loop=False,
            did=did_1,
            url=url,
            notification_email="thierry@altme.io",
            status="active",
            admins_identity_provider="google",
            admins_login=json.dumps(["thierry.thevenet@talao.io"]),
            did_document=create_did_document(did_1, jwk, url)
        )
        db.session.add(wallet_1)
        
        vm = "did:web:wallet4agent.com:demo2#key-1"
        key_id = manager.create_or_get_key_for_tenant(vm)
        jwk, kid, alg = manager.get_public_key_jwk(key_id)
        did = "did:web:wallet4agent.com:demo2"
        url = mode.server  + did
        admin_pat, admin_pat_jti = oidc4vc.generate_access_token(did, "admin", "pat", jti="demo2")
        agent_pat, agent_pat_jti = oidc4vc.generate_access_token(did, "admin", "pat", jti="demo2", duration=90*24*60*60)
        wallet_2 = Wallet(
            admin_pat_jti=admin_pat_jti,
            agent_pat_jti=agent_pat_jti,
            always_human_in_the_loop=True,
            did=did,
            status="active",
            url=url,
            admins_identity_provider="google",
            admins_login=json.dumps(["thierry.thevenet@talao.io"]),
            did_document=create_did_document(did, jwk, url)
        )
        db.session.add(wallet_2)
        
        did = "did:web:wallet4agent.com:diipv4"
        vm = did + "#key-1"
        key_id = manager.create_or_get_key_for_tenant(vm)
        jwk, kid, alg = manager.get_public_key_jwk(key_id)
        url = mode.server + did
        admin_pat, admin_pat_jti = oidc4vc.generate_access_token(did, "admin", "pat", jti="diipv4")
        agent_pat, agent_pat_jti = oidc4vc.generate_access_token(did, "admin", "pat", jti="diipv4", duration=90*24*60*60)
        wallet_3 = Wallet(
            admin_pat_jti=admin_pat_jti,
            agent_pat_jti=agent_pat_jti,
            ecosystem_profile="DIIP V4",
            always_human_in_the_loop=False,
            did=did,
            status="active",
            url=url,
            admins_identity_provider="google",
            admins_login=json.dumps(["thierry.thevenet@talao.io"]),
            did_document=create_did_document(did, jwk, url)
        )
        db.session.add(wallet_3)
        
        did = "did:web:wallet4agent.com:ewc"
        vm = did + "#key-1"
        key_id = manager.create_or_get_key_for_tenant(vm)
        jwk, kid, alg = manager.get_public_key_jwk(key_id)
        url = mode.server + did
        admin_pat, admin_pat_jti = oidc4vc.generate_access_token(did, "admin", "pat", jti="ewc")
        agent_pat, agent_pat_jti = oidc4vc.generate_access_token(did, "admin", "pat", jti="ewc", duration=90*24*60*60)
        wallet_4 = Wallet(
            admin_pat_jti=admin_pat_jti,
            agent_pat_jti=agent_pat_jti,
            ecosystem_profile="EWC",
            always_human_in_the_loop=False,
            did=did,
            status="active",
            url=url,
            admins_identity_provider="google",
            admins_login=json.dumps(["thierry.thevenet@talao.io"]),
            did_document=create_did_document(did, jwk, url)
        )
        db.session.add(wallet_4)
        
        did = "did:web:wallet4agent.com:arf"
        vm = did + "#key-1"
        key_id = manager.create_or_get_key_for_tenant(vm)
        jwk, kid, alg = manager.get_public_key_jwk(key_id)
        url = mode.server + did
        admin_pat, admin_pat_jti = oidc4vc.generate_access_token(did, "admin", "pat", jti="arf")
        agent_pat, agent_pat_jti = oidc4vc.generate_access_token(did, "admin", "pat", jti="arf", duration=90*24*60*60)
        wallet_5 = Wallet(
            admin_pat_jti=admin_pat_jti,
            agent_pat_jti=agent_pat_jti,
            ecosystem_profile="ARF",
            always_human_in_the_loop=False,
            did=did,
            status="active",
            url=url,
            admins_identity_provider="google",
            admins_login=json.dumps(["thierry.thevenet@talao.io"]),
            did_document=create_did_document(did, jwk, url)
        )
        db.session.add(wallet_5)
        
        db.session.commit()


def seed_user():
    if not User.query.first():
        default_user = User(
            email="thierry.thevenet@talao.io",
            created_at=datetime.now(timezone.utc),
            registration="initialisation",
            role="admin",
            organization="Web3 Digital Wallet",
            subscription="paid",
        )
        db.session.add(default_user)        
        db.session.commit()



def create_did_document(did, jwk_1, url) -> str:
    document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            {
                "publicKeyJwk": {
                    "@id": "https://w3id.org/security#publicKeyJwk",
                    "@type": "@json"
                }
            }
        ],
        "id": did,
        "verificationMethod": [ 
            {
                "id": did + "#key-1",
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": jwk_1
            }
        ],
        "authentication":[
            did + "#key-1"
        ],  
        "assertionMethod" : [
            did + "#key-1",
        ],
        "service": [
            {
                "id": did + "#oidc4vp",
                "type": "OIDC4VP",
                "serviceEndpoint": url
            }  
        ]
    }
    return json.dumps(document)


