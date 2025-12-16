from flask import Flask, request, jsonify, current_app, redirect
import base64
import datetime
import uuid
import logging
import json
import time

from db_model import Wallet
from utils import oidc4vc

from jwcrypto import jwk, jws  # <-- use jwcrypto, not pyjwt


def init_app(app):
    # Authorization server endpoint for MCP server
    app.add_url_rule('/.well-known/oauth-authorization-server', view_func=oauth_metadata, methods=['GET'])    
    app.add_url_rule('/.well-known/openid-configuration', view_func=oauth_metadata, methods=['GET'])
    app.add_url_rule('/oauth/token', view_func=token, methods=['GET', 'POST'])

    return


def _b64url_decode(segment: str) -> bytes:
    # Helper to decode JWT segments without padding issues
    padding = '=' * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def authenticate_client():
    """
    Try to authenticate the client using:
        1. Client Secret Basic
        2. Client Secret Post
        3. Client Assertion JWT (private_key_jwt) with jwcrypto and Wallet.client_public_key

    Returns: (client_id or None, error_message or None)
    """

    # --- 1. CLIENT SECRET BASIC ---
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Basic "):
        logging.info("Client Secret Basic")
        try:
            decoded = base64.b64decode(auth_header.split(" ")[1]).decode()
            # IMPORTANT: split from the RIGHT so DIDs with ':' are preserved
            client_id, client_secret = decoded.rsplit(":", 1)

            wallet = Wallet.query.filter(Wallet.agent_identifier == client_id).first()
            if not wallet:
                logging.warning("Basic auth: no wallet found for did=%s", client_id)
                return None, "invalid_client_credentials"

            client_secret_hash = oidc4vc.hash_client_secret(client_secret)
            logging.debug(
                "Basic auth: computed hash=%s, stored hash=%s",
                client_secret_hash,
                wallet.client_secret_hash,
            )

            if wallet.client_secret_hash == client_secret_hash:
                return client_id, None

            logging.warning("Basic auth: hash mismatch for did=%s", client_id)
            return None, "invalid_client_credentials"
        except Exception:
            logging.exception("Error while processing Basic auth")
            return None, "invalid_basic_auth"

    # --- 2. CLIENT SECRET POST ---
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")

    if client_id and client_secret:
        logging.info("Client Secret Post")
        wallet = Wallet.query.filter(Wallet.agent_identifier == client_id).first()
        if not wallet:
            logging.warning("Post auth: no wallet found for did=%s", client_id)
            return None, "invalid_client_credentials"

        client_secret_hash = oidc4vc.hash_client_secret(client_secret)
        logging.debug(
            "Post auth: computed hash=%s, stored hash=%s",
            client_secret_hash,
            wallet.client_secret_hash,
        )

        if wallet.client_secret_hash == client_secret_hash:
            return client_id, None

        logging.warning("Post auth: hash mismatch for did=%s", client_id)
        return None, "invalid_client_credentials"

    # --- 3. CLIENT ASSERTION JWT (private_key_jwt) ---
    client_assertion = request.form.get("client_assertion")
    client_assertion_type = request.form.get("client_assertion_type")

    if client_assertion and client_assertion_type == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
        logging.info("Client Assertion JWT (private_key_jwt)")

        try:
            # Parse JWT header and payload first (unverified) to get 'sub' (client_id)
            parts = client_assertion.split(".")
            if len(parts) != 3:
                return None, "invalid_client_assertion"

            header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
            payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))

            client_id = payload.get("sub")
            iss = payload.get("iss")
            aud = payload.get("aud")
            exp = payload.get("exp")

            if not client_id or not iss:
                return None, "invalid_client_assertion"

            # iss and sub must match the client identifier
            if iss != client_id:
                return None, "invalid_client_assertion"

            # Load wallet & public key from DB
            wallet = Wallet.query.filter(Wallet.agent_identifier == client_id).first()
            if not wallet or not wallet.client_public_key:
                logging.warning("JWT auth: no wallet or public key for did=%s", client_id)
                return None, "unknown_client"

            # Public JWK is stored as JSON string (public key only, no 'd')
            try:
                pub_jwk_dict = json.loads(wallet.client_public_key)
            except Exception:
                logging.exception("Invalid public JWK in wallet")
                return None, "invalid_client_configuration"

            key = jwk.JWK(**pub_jwk_dict)

            # Verify signature using jwcrypto JWS
            jws_token = jws.JWS()
            jws_token.deserialize(client_assertion)
            
            try:
                jws_token.verify(key)
            except Exception as e:
                logging.warning(str(e))
                return None, "invalid_client_assertion"
                
                
            # Validate 'aud' against this token endpoint URL
            token_endpoint_url = request.base_url  # e.g. http://host:port/oauth/token

            if isinstance(aud, list):
                if token_endpoint_url not in aud:
                    return None, "invalid_client_assertion_aud"
            elif isinstance(aud, str):
                if aud != token_endpoint_url:
                    return None, "invalid_client_assertion_aud"
            else:
                return None, "invalid_client_assertion_aud"

            # Check expiration
            if exp is not None:
                now = int(time.time())
                if now > int(exp):
                    return None, "invalid_client_assertion_expired"

            # All good
            return client_id, None

        except Exception:
            logging.exception("Error while verifying client_assertion")
            return None, "invalid_client_assertion"

    # No recognized authentication found
    return None, "authentication_required"




# MCP server AS token endpoint
def token():
    client_id, error = authenticate_client()
    if error:
        return (
            jsonify({
                "error": "invalid_client", 
                "error_description": error
            }),
            401,
        )

    # issue access token which are encrypted and not signed
    access_token, jti = oidc4vc.generate_access_token(client_id, "agent", "oauth", duration=30*60)
    
    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 1800
    })


def oauth_metadata():
    mode = current_app.config["MODE"]
    metadata = {
        "issuer": mode.server,
        "token_endpoint": mode.server + "oauth/token",

        "grant_types_supported": [
            "client_credentials",
            #"authorization_code",
            #"refresh_token"
        ],

        "response_types_supported": [
            "token"
        ],

        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt"
        ],

        "token_endpoint_auth_signing_alg_values_supported": [
            "RS256",
            "ES256"
        ]
    }
    return jsonify(metadata)


# In-memory authorization code store (DEMO ONLY)
AUTHORIZATION_CODES = {}

# Registered redirect URIs (demo)
A_CLIENTS = {
    "client_basic": {
        "redirect_uris": ["http://localhost:6274/oauth/callback"]
    },
    "client_post": {
        "redirect_uris": ["http://localhost:6274/oauth/callback"]
    },
    "client_jwt": {
        "redirect_uris": ["http://localhost:6274/oauth/callback"]
    }
}


def authorize():
    """
    Minimal OAuth2 Authorization Endpoint
    Supports: response_type=code
    """

    response_type = request.args.get("response_type")
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    scope = request.args.get("scope")
    state = request.args.get("state")

    # ---- 1. Validate mandatory parameters ----
    if response_type != "code":
        return jsonify({"error": "unsupported_response_type"}), 400

    if client_id not in A_CLIENTS:
        return jsonify({"error": "invalid_client"}), 400

    if redirect_uri not in A_CLIENTS[client_id]["redirect_uris"]:
        return jsonify({"error": "invalid_redirect_uri"}), 400

    # ---- 2. Simulate login and consent ----
    # In real servers, you would:
    #   - authenticate user
    #   - show consent screen
    #
    # Here we skip both steps (minimal example).
    user_id = "demo-user"

    # ---- 3. Generate authorization code ----
    auth_code = str(uuid.uuid4())

    AUTHORIZATION_CODES[auth_code] = {
        "client_id": client_id,
        "user_id": user_id,
        "scope": scope,
        "expires_at": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
    }

    # ---- 4. Redirect with ?code=xxx&state=yyy ----
    redirect_url = f"{redirect_uri}?code={auth_code}"
    if state:
        redirect_url += f"&state={state}"

    return redirect(redirect_url, code=302)
