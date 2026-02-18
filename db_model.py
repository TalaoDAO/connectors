from datetime import datetime
from utils import oidc4vc
import logging
from database import db

from utils.did_document import create_did_document


def get_wallet_by_wallet_identifier(wallet_identifier: str):
    return Wallet.query.filter_by(wallet_identifier=wallet_identifier).one_or_none()


def list_wallets_by_agent_identifier(agent_identifier: str):
    return Wallet.query.filter_by(agent_identifier=agent_identifier).all()

import uuid



class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)   # internal identifier
    type = db.Column(db.String(64), default="agent")
    owner = db.Column(db.String(256))
    admin_pat_jti = db.Column(db.String(64))
    agent_pat_jti = db.Column(db.String(64))
    agentcard_url = db.Column(db.Text)
    log = db.Column(db.Boolean, default=False)
    client_secret_hash = db.Column(db.String(64))
    client_public_key = db.Column(db.Text)
    mcp_authentication = db.Column(db.String(256), default="Personal Access Token (PAT)")
    notification_email = db.Column(db.String(256))
    ecosystem_profile = db.Column(db.String(64), default="DIIP V3")
    url = db.Column(db.Text)
    linked_vp = db.Column(db.Text, default="{}")
    is_chat_agent = db.Column(db.Boolean, default=False)
    chat_profile = db.Column(db.String(256))
    agent_identifier = db.Column(db.Text, index=True)
    wallet_identifier = db.Column(db.Text, unique=True, index=True)
    did_document = db.Column(db.Text)
    status = db.Column(db.String(256), default="pending")
    sign = db.Column(db.Boolean, default=True)
    receive_credentials = db.Column(db.Boolean, default=True)
    publish_unpublish = db.Column(db.Boolean, default=True)
    publish_OBO = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    
class Attestation(db.Model):
    id = db.Column(db.Integer, primary_key=True)   # internal identifier
    wallet_identifier = db.Column(db.Text, index=True)
    agent_identifier = db.Column(db.Text, index=True)
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


def seed_wallet(mode, manager):
    talao = "did:web:talao.co"
    if not Wallet.query.first():
        vm = "did:web:talao.io:#key-2"
        key_id = 1
        did = "did:web:talao.co"
        wallet_identifier = str(uuid.uuid4())
        url = f"{mode.server.rstrip('/')}/wallets/{wallet_identifier}"
        admin_pat, admin_pat_jti = oidc4vc.generate_access_token(did, "admin", "pat", jti="talao")
        agent_pat, agent_pat_jti = oidc4vc.generate_access_token(did, "admin", "pat", jti="talao", duration=90*24*60*60)
        agentcard_url = mode.server + ".well-known/agent-card.json"
        wallet_0 = Wallet(
            admin_pat_jti=admin_pat_jti,  # 365 days
            agent_pat_jti=agent_pat_jti,
            owner=talao,
            type="company",
            agent_identifier=did,
            wallet_identifier=wallet_identifier,
            agentcard_url=agentcard_url,
            ecosystem_profile="DIIP V3",
            url=url,
            notification_email="thierry.tevenet@talao.io",
            status="active",
            did_document=None
        )
        db.session.add(wallet_0)
        
        vm = "did:web:wallet4agent.com:demo#key-1"
        key_id = manager.create_or_get_key_for_tenant(vm)
        jwk, kid, alg = manager.get_public_key_jwk(key_id)
        did = "did:web:wallet4agent.com:demo"
        wallet_identifier = str(uuid.uuid4())
        url = f"{mode.server.rstrip('/')}/wallets/{wallet_identifier}"
        admin_pat, admin_pat_jti = oidc4vc.generate_access_token(did, "admin", "pat", jti="demo")
        agent_pat, agent_pat_jti = oidc4vc.generate_access_token(did, "admin", "pat", jti="demo", duration=90*24*60*60)
        agentcard_url = mode.server + ".well-known/agent-card.json"
        wallet_1 = Wallet(
            admin_pat_jti=admin_pat_jti,  # 365 days
            agent_pat_jti=agent_pat_jti,
            owner=talao,
            agent_identifier=did,
            wallet_identifier=wallet_identifier,
            agentcard_url=agentcard_url,
            ecosystem_profile="DIIP V3",
            url=url,
            notification_email="thierry@altme.io",
            status="active",
            did_document=create_did_document(did, jwk, wallet_identifier, talao, mode, agentcard_url)
        )
        db.session.add(wallet_1)
        
        did = "did:web:wallet4agent.com:eudiw"
        vm = did + "#key-1"
        key_id = manager.create_or_get_key_for_tenant(vm)
        jwk, kid, alg = manager.get_public_key_jwk(key_id)
        wallet_identifier = str(uuid.uuid4())
        url = f"{mode.server.rstrip('/')}/wallets/{wallet_identifier}"
        admin_pat, admin_pat_jti = oidc4vc.generate_access_token(did, "admin", "pat", jti="eudiw")
        agent_pat, agent_pat_jti = oidc4vc.generate_access_token(did, "admin", "pat", jti="eudiw", duration=90*24*60*60)
        wallet_5 = Wallet(
            admin_pat_jti=admin_pat_jti,
            agent_pat_jti=agent_pat_jti,
            owner=talao,
            ecosystem_profile="EUDIW",
            agent_identifier=did,
            wallet_identifier=wallet_identifier,
            notification_email="thierry@altme.io",
            status="active",
            url=url,
            did_document=create_did_document(did, jwk, wallet_identifier, talao, mode, None)
        )
        db.session.add(wallet_5)
        
        key_id = manager.create_or_get_key_for_tenant(vm)
        jwk, kid, alg = manager.get_public_key_jwk(key_id)
        wallet_identifier = "local"
        url = f"{mode.server.rstrip('/')}/wallets/{wallet_identifier}"
        admin_pat, admin_pat_jti = oidc4vc.generate_access_token(did, "admin", "pat", jti="local")
        agent_pat, agent_pat_jti = oidc4vc.generate_access_token(did, "admin", "pat", jti="local", duration=90*24*60*60)
        wallet_6 = Wallet(
            admin_pat_jti=admin_pat_jti,
            owner=talao,
            agent_pat_jti=agent_pat_jti,
            agentcard_url=mode.server + "local/.well-known/agent-card.json",
            ecosystem_profile="DIIP V3",
            agent_identifier="local",
            wallet_identifier=wallet_identifier,
            notification_email="thierry@altme.io",
            status="active",
            url=url,
        )
        db.session.add(wallet_6)
        
        db.session.commit()


