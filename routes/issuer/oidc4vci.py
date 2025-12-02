"""
NEW
https://issuer.walt.id/issuer-api/default/oidc
EBSI V2 https://openid.net/specs/openid-connect-4-verifiable-credential-issuance-1_0-05.html
support Authorization code flow and pre-authorized code flow of OIDC4VCI
"""
import json
import logging
import random
import uuid
from datetime import datetime, timedelta
from random import randint
from urllib.parse import urlencode
import pkce
import requests
from flask import (Response, flash, jsonify, redirect,
                render_template, request, session, current_app)
import didkit
from utils import x509_attestation, signer, oidc4vc
from db_model import Issuer, Credential, User
from routes.issuer import build_issuer_metadata
from kms_model import decrypt_json


logging.basicConfig(level=logging.INFO)

API_LIFE = 5000
ACCESS_TOKEN_LIFE = 10000
GRANT_LIFE = 5000
C_NONCE_LIFE = 5000
ACCEPTANCE_TOKEN_LIFE = 28 * 24 * 60 * 60
STATUSLIST_ISSUER_KEY = json.dumps(json.load(open('keys.json', 'r'))['credentials'][0]["key"])


def init_app(app):
    
    # endpoint for application to get the qrcode value
    app.add_url_rule('/application/issuer/qrcode/<issuer_id>/<session_id>', view_func=oidc_issuer_qrcode_value, methods=['GET', 'POST'])
    
    # OIDC4VCI protocol with wallet
    app.add_url_rule('/issuer/<issuer_id>/.well-known/openid-credential-issuer', view_func=credential_issuer_openid_configuration_endpoint, methods=['GET'])
    
    # AS endpoint when issuer = AS
    #app.add_url_rule('/issuer/<issuer_id>/.well-known/openid-configuration', view_func=openid_configuration, methods=['GET'])
    app.add_url_rule('/issuer/<issuer_id>/.well-known/oauth-authorization-server', view_func=oauth_authorization_server, methods=['GET'])
    app.add_url_rule('/issuer/<issuer_id>/authorize', view_func=issuer_authorize, methods=['GET'])
    app.add_url_rule('/issuer/<issuer_id>/authorize/par', view_func=issuer_authorize_par, methods=['POST'])
    app.add_url_rule('/issuer/<issuer_id>/token', view_func=issuer_token, methods=['POST'])
    
    # Issuer endpoint
    app.add_url_rule('/issuer/<issuer_id>/credential', view_func=issuer_credential, methods=['POST'])
    app.add_url_rule('/issuer/credential_offer_uri/<id>', view_func=issuer_credential_offer_uri)
    app.add_url_rule('/issuer/nonce', view_func=issuer_nonce, methods=['POST'])

    app.add_url_rule('/issuer/error_uri', view_func=wallet_error_uri, methods=['GET'])
        
    # login with login/password authorization code flow
    app.add_url_rule('/issuer/<issuer_id>/authorize/login', view_func=issuer_authorize_login, methods=['GET', 'POST'])
    # login with PID authorization code flow
    app.add_url_rule('/issuer/<issuer_id>/authorize/pid', view_func=issuer_authorize_pid, methods=['POST'])

    # keys for  sd-jwt vc
    app.add_url_rule('/.well-known/jwt-vc-issuer/issuer/<issuer_id>', view_func=openid_jwt_vc_issuer_configuration, methods=['GET'])

    # keys for jwt_vc_json and jwt_vc_json-ld
    app.add_url_rule('/issuer/<issuer_id>/jwks', view_func=issuer_jwks, methods=['GET'])

    return


def wallet_error_uri():
    error = request.args.get('error')
    error_description = request.args.get('error_description')
    header = request.args.get('header')
    body = request.args.get('body')
    arguments = request.args.get('arguments')
    return render_template(
        'issuer_oidc/issuer_error_uri.html',
        header=header,
        error=error,
        error_description=error_description,
        body=body,
        arguments=arguments
    )


def error_uri_build(request, error, error_description, mode):
    if request.headers.get('Content-Type') == 'application/json':
        body = json.dumps(request.json)
    elif not request.headers.get('Content-Type'):
        body = ''
    else:
        body = json.dumps(request.form)

    data = {
        'header': str(request.headers),
        'arguments': json.dumps(request.args),
        'body': body,
        'error': error,
        'error_description': error_description
    }
    return mode.server + 'issuer/error_uri?' + urlencode(data)


def manage_error(error, error_description, red, mode, status=400, webhook_data=None):
    """
    Return error code to wallet and front channel
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-error-response
    """
    if webhook_data:
        issuer = Issuer.query.filter(Issuer.application_api_issuer_id == webhook_data.get('issuer_id')).one_or_none()
        if issuer:
            webhook_data['error_description'] = error_description
            push_to_webhook(issuer.webhook_url, webhook_data)
        else:
            logging.error("issuer does not exist , cannot send Error event")

    # wallet
    payload = {
        'error': error,
        'error_description': error_description,
    }
    if error == 'invalid_proof':
        payload['c_nonce'] = str(uuid.uuid1())
        payload['c_nonce_expires_in'] = 86400
    
    logging.info('endpoint error response = %s', json.dumps(payload, indent=4))

    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return {'response': json.dumps(payload), 'status': status, 'headers': headers}


def build_signed_metadata(issuer_id, metadata) -> str:
    mode = current_app.config["MODE"]
    sub = mode.server + 'issuer/' + issuer_id
    issuer = Issuer.query.filter(Issuer.application_api_issuer_id == issuer_id).one_or_none()
    user_id = issuer.user_id
    credential = Credential.query.filter(Credential.credential_id == issuer.credential_id).first()
    user = User.query.filter_by(id=user_id).first()
    key = decrypt_json(credential.key)
    alg = oidc4vc.alg(key)
    header = {
        'typ': "openidvci-issuer-metadata+jwt",
        'alg': alg,
    }
    header['x5c'] = x509_attestation.build_x509_san_dns()
    payload = {
        'sub': sub,
        'iat': int(datetime.timestamp(datetime.now()))
    }
    payload |= metadata
    jwt = signer.sign_jwt(user.qtsp_account(), credential, header, payload)
    return jwt


# credential issuer openid configuration endpoint
def credential_issuer_openid_configuration_endpoint(issuer_id):
    logging.info('Call credential issuer configuration endpoint')
    metadata = build_credential_issuer_metadata(issuer_id)
    issuer = Issuer.query.filter(Issuer.application_api_issuer_id == issuer_id).one_or_none()
    if not issuer or not metadata:
        return Response(
            response=json.dumps({"error": "issuer_not_found ot no metadata"}),
            status=404,
            headers={"Cache-Control": "no-store", "Content-Type": "application/json"},
        )
    issuer_metadata = build_signed_metadata(issuer_id, metadata)
    
    # Event to application
    webhook_data = {
            'event': 'CREDENTIAL_ISSUER_METADATA_REQUIRED',
            'issuer_id': issuer_id,
            'issuer_metadata' : issuer_metadata
    }
    push_to_webhook(issuer.webhook_url, webhook_data)
    
    if issuer.signed_metadata and int(issuer.draft) < 15:
        metadata["signed_metadata"] = issuer_metadata
        headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
        return Response(response=json.dumps(metadata), headers=headers)
    elif issuer.signed_metadata:
        headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/jwt'}
        return Response(issuer_metadata, headers=headers)
    else:
        headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
        return Response(response=json.dumps(metadata), headers=headers)
    
        
def build_credential_issuer_metadata(issuer_id):
    return build_issuer_metadata.build_credential_issuer_metadata(issuer_id)


# jwt vc issuer openid configuration
def openid_jwt_vc_issuer_configuration(issuer_id) -> str:
    mode = current_app.config["MODE"]
    issuer = Issuer.query.filter(Issuer.application_api_issuer_id == issuer_id).one_or_none()
    if not issuer:
        return jsonify({"error": "issuer_not_found"}), 404
    credential = Credential.query.filter(Credential.credential_id == issuer.credntial_id).one_or_none()
    if not credential:
        return jsonify({"error": "credential_not_found"}), 404
    pub_key = json.loads(credential.public_key)
    pub_key['kid'] = pub_key.get('kid') if pub_key.get('kid') else oidc4vc.thumbprint(pub_key)
    jwks = {'keys': [pub_key]}
    choice_bool = random.choice([True, False])
    if choice_bool:
        config = {
            'issuer': mode.server + 'issuer/' + issuer_id,
            'jwks': jwks
        }
    else:
        config = {
            'issuer': mode.server + 'issuer/' + issuer_id,
            'jwks_uri': mode.server + 'issuer/' + issuer_id + '/jwks'
        }
    logging.info('jwks for sd-jwt config = %s', config)
    return jsonify(config)


# authorization server configuration 
def build_authorization_server_openid_configuration(issuer_id, mode):
    #issuer = Issuer.query.filter(Issuer.application_api_issuer_id == issuer_id).one_or_none()
    authorization_server_config = json.load(open('authorization_server_config.json'))
    config = {
        'issuer': mode.server + 'issuer/' + issuer_id,
        'authorization_endpoint': mode.server + 'issuer/' + issuer_id + '/authorize',
        'token_endpoint': mode.server + 'issuer/' + issuer_id + '/token',
        'jwks_uri':  mode.server + 'issuer/' + issuer_id + '/jwks',
        'pushed_authorization_request_endpoint': mode.server +'issuer/' + issuer_id + '/authorize/par' ,
        'pre-authorized_grant_anonymous_access_supported': True
    }
    config.update(authorization_server_config)
    return config



# /.well-known/openid-configuration endpoint  authorization server endpoint for draft 11 DEPRECATED
def openid_configuration(issuer_id):
    mode = current_app.config["MODE"]
    issuer = Issuer.query.filter(Issuer.application_api_issuer_id == issuer_id).one_or_none()
    logging.warning('Call to openid-configuration endpoint')
    if int(issuer.draft) >= 13:
        message = {'error': 'access_denied', 'error_description': 'invalid endpoint'}
        return jsonify(message), 404
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    config = build_authorization_server_openid_configuration(issuer_id, mode)
    return Response(response=json.dumps(config), headers=headers)    #return jsonify(as_openid_configuration(issuer_id, mode))



# /.well-known/oauth-authorization-server endpoint
def oauth_authorization_server(issuer_id):
    mode = current_app.config["MODE"]
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    logging.info('Call to oauth-authorization-server endpoint')
    config = build_authorization_server_openid_configuration(issuer_id, mode)
    return Response(response=json.dumps(config), headers=headers)


# /standalone/.well-known/oauth-authorization-server endpoint
def standalone_oauth_authorization_server(issuer_id):
    mode = current_app.config["MODE"]
    issuer = Issuer.query.filter(Issuer.application_api_issuer_id == issuer_id).one_or_none()

    logging.info('Call to the standalone oauth-authorization-server endpoint')
    if not issuer.authorization_server:
        logging.error('CALL TO WRONG AUTHORIZATION SERVER')
        message = {'error': 'access_denied', 'error_description': 'invalid authorization server'}
        return jsonify(message), 404
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    authorization_server_config = json.load(open('authorization_server_config.json'))
    config = {
        'issuer': mode.server + 'issuer/' + issuer_id + '/standalone',
        'authorization_endpoint': mode.server + 'issuer/' + issuer_id + '/standalone/authorize',
        'token_endpoint': mode.server + 'issuer/' + issuer_id + '/standalone/token',
        'jwks_uri':  mode.server + 'issuer/' + issuer_id + '/jwks',
        'pushed_authorization_request_endpoint': mode.server + 'issuer/' + issuer_id + '/standalone/authorize/par' ,
        'pre-authorized_grant_anonymous_access_supported': True
    }
    config.update(authorization_server_config)
    return Response(response=json.dumps(config), headers=headers)



# jwks endpoint
def issuer_jwks(issuer_id):
    issuer = Issuer.query.filter(Issuer.application_api_issuer_id == issuer_id).one_or_none()
    if not issuer:
        return jsonify({"error": "issuer_not_found"}), 404
    credential = Credential.query.filter(Credential.credential_id == issuer.credential_id).first()
    if not credential:
        return jsonify({"error": "credential_not_found"}), 404
    pub_key = json.loads(credential.public_key)
    pub_key['kid'] = pub_key.get('kid') if pub_key.get('kid') else oidc4vc.thumbprint(pub_key)
    jwks = {'keys': [pub_key]}
    logging.info('issuer jwks = %s', jwks)
    return jsonify(jwks)


def build_credential_offer(session_id, red, mode):
    # OIDC4VCI standard with credentials as an array ofjson objects (EBSI-V3)
    try:
        session_data = json.loads(red.get(session_id).decode())
    except Exception as e:
        return 
    issuer_id = session_data.get("issuer_id")
    grant_type = session_data.get("grant_type")
    
    issuer = Issuer.query.filter(Issuer.application_api_issuer_id == issuer_id).one_or_none()
    if not issuer:
        return
    
    issuer_vc_type = json.loads(issuer.vc_type or "[]")
    credential_identifier_list = []
    for vct_obj in issuer_vc_type: 
        credential_identifier = vct_obj.get('credential_identifier')
        credential_identifier_list.append(credential_identifier) 
    
    if issuer.draft == '11':
        # https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html
        offer = {
            'credential_issuer': f'{mode.server}issuer/{issuer_id}',
            'credentials': credential_identifier_list,
        }
        if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
            offer['grants'] = {
                'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
                    'pre-authorized_code': session_data.get("pre-authorized_code")
                }
            }
            if issuer.tx_code_required:
                offer['grants'][
                    'urn:ietf:params:oauth:grant-type:pre-authorized_code'
                ].update({'user_pin_required': True})
        else:
            offer['grants'] = {
                'authorization_code': {
                    'issuer_state': session_data.get("issuer_state")
                }
            }

    else:  # Draft 13
        offer = {
            'credential_issuer': f'{mode.server}issuer/{issuer_id}',
            'credential_configuration_ids': credential_identifier_list,
        }
        if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
            offer['grants'] = {
                'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
                    'pre-authorized_code': session_data.get("pre-authorized_code")
                }
            }
            if issuer.authorization_server and int(issuer.draft) >= 13:
                offer['grants']['urn:ietf:params:oauth:grant-type:pre-authorized_code'].update({'authorization_server': issuer.authorization_server})
            if issuer.tx_code_required:
                offer['grants'][
                    'urn:ietf:params:oauth:grant-type:pre-authorized_code'
                ].update({
                    'tx_code': {
                        'length': issuer.tx_code_length,
                        'input_mode': issuer.tx_code_input_mode,
                        'description': issuer.tx_code_description
                    }
                })
        else:
            offer['grants'] = {
                'authorization_code': {
                    'issuer_state': session_data.get("issuer_state")
                }
            }
            if issuer.authorization_server and int(issuer.draft) >= 13:
                offer['grants']['authorization_code'].update({'authorization_server': issuer.authorization_server}) 
    print("offer = ", offer)
    return offer


# credential offer uri endpoint
def issuer_credential_offer_uri(id):
    red = current_app.config["REDIS"]
    """
    credential_offer_uri endpoint
    return 201
    """
    try:
        offer = json.loads(red.get(id).decode())
    except Exception:
        logging.warning('session expired')
        return jsonify('Session expired'), 404
    return jsonify(offer), 201


# Return QRcode value to application API
def oidc_issuer_qrcode_value(issuer_id, session_id):
    red = current_app.config["REDIS"]
    mode = current_app.config["MODE"]
    
    try:
        session_data = json.loads(red.get(session_id).decode())
    except Exception:
        logging.warning('session expired')
        return jsonify('Session expired'), 404
    
    issuer = Issuer.query.filter(Issuer.application_api_issuer_id == issuer_id).one_or_none()
    
    # Get offer
    offer = build_credential_offer(session_id, red,  mode)
    
    # credential offer is passed by value
    url_to_display = issuer.prefix + '?' + urlencode({'credential_offer': json.dumps(offer)})

    # credential offer is passed by reference: credential offer uri
    if issuer.credential_offer_uri:
        id = str(uuid.uuid1())
        credential_offer_uri = (
            f'{mode.server}issuer/credential_offer_uri/{id}'
        )
        red.setex(id, GRANT_LIFE, json.dumps(offer))
        logging.info('credential offer uri = %s', credential_offer_uri)
        url_to_display = (
            issuer.prefix
            + '?credential_offer_uri='
            + credential_offer_uri
        )        
    return jsonify({'qrcode_value': url_to_display})


def authorization_error(error, error_description, red, state):
    """
    https://www.rfc-editor.org/rfc/rfc6749.html#page-26
    """
    resp = {
        'error_description': error_description,
        'error': error
    }
    # front channel follow up
    if state:
        resp['state'] = state
    return urlencode(resp)


# pushed authorization endpoint endpoint
def issuer_authorize_par(issuer_id):
    red = current_app.config["REDIS"]
    mode = current_app.config["MODE"]
    logging.info('request header = %s', request.headers)
    logging.info('request body = %s', json.dumps(request.form, indent=4))
    
    # setup webhook_data for Error event
    webhook_data = {
        'event': 'ERROR',
        'issuer_id': issuer_id,
    }
    
    # DPoP
    if request.headers.get('DPoP'):
        try:
            DPoP_header = oidc4vc.get_header_from_token(request.headers.get('DPoP'))
            DPoP_payload = oidc4vc.get_payload_from_token(request.headers.get('DPoP'))
            logging.info('DPoP header = %s', json.dumps(DPoP_header, indent=4))
            logging.info('DPoP payload = %s', json.dumps(DPoP_payload, indent=4))
        except Exception as e:
            return Response(**manage_error('invalid_request', 'DPoP is incorrect ' + str(e), red, mode, webhook_data=webhook_data))
    else:
        logging.info('No DPoP')
    
    issuer = Issuer.query.filter(Issuer.application_api_issuer_id == issuer_id).one_or_none()
    if not issuer:
        return Response(**manage_error('invalid_request', 'client_id does not match client assertion sub', red, mode, webhook_data=webhook_data))
    
    # test if a standalone AS is used
    if issuer.authorization_server and int(issuer.draft) >= 13:
        return Response(**manage_error('invalid_request', 'invalid authorization server', red, mode, webhook_data=webhook_data))
    
    # Check content of client assertion and proof of possession (DPoP)
    if request.form.get('client_assertion'):
        client_assertion = request.form.get('client_assertion').split('~')[0]
        logging.info('client _assertion = %s', client_assertion)
        if request.form.get('client_id') != oidc4vc.get_payload_from_token(client_assertion).get('sub'):
            return Response(**manage_error('invalid_request', 'client_id does not match client assertion sub', red, mode, webhook_data=webhook_data))
        try:
            DPoP = request.form.get('client_assertion').split('~')[1]
        except Exception:
            return Response(**manage_error('invalid_request', 'PoP is missing', red, mode, webhook_data=webhook_data))
        logging.info('proof of possession = %s', DPoP)
        if oidc4vc.get_payload_from_token(client_assertion).get('sub') != oidc4vc.get_payload_from_token(DPoP).get('iss'):
            return Response(**manage_error('invalid_request', 'sub of client assertion does not match proof of possession iss', red, mode, webhook_data=webhook_data))
    
    elif request.headers.get('Oauth-Client-Attestation'):
        client_assertion = request.headers.get('Oauth-Client-Attestation')
        logging.info('OAuth-Client-Attestation = %s', client_assertion)
        if request.form.get('client_id') != oidc4vc.get_payload_from_token(client_assertion).get('sub'):
            return Response(**manage_error('invalid_request', 'client_id does not match client assertion sub', red, mode, webhook_data=webhook_data))
        try:
            DPoP = request.headers.get('Oauth-Client-Attestation-Pop')
        except Exception:
            return Response(**manage_error('invalid_request', 'PoP is missing', red, mode, webhook_data=webhook_data))
        logging.info('OAuth-Client-Attestation-PoP = %s', DPoP)
        if oidc4vc.get_payload_from_token(client_assertion).get('sub') != oidc4vc.get_payload_from_token(DPoP).get('iss'):
            return Response(**manage_error('invalid_request', 'sub of client assertion does not match proof of possession iss', red, mode, webhook_data=webhook_data))
    else:
        logging.warning('No client assertion / wallet attestation')
    try:
        request_uri_data = {
            'redirect_uri': request.form['redirect_uri'],
            'client_id': request.form['client_id'],
            'response_type': request.form['response_type'],
            'scope': request.form['scope'],
            'issuer_state': request.form.get('issuer_state'),
        }
    except Exception:
        return Response(**manage_error('invalid_request', 'Request format is incorrect', red, mode, webhook_data=webhook_data))
    request_uri_data.update({
        'nonce': request.form.get('nonce'),
        'code_challenge': request.form.get('code_challenge'),
        'code_challenge_method': request.form.get('code_challenge_method'),
        'client_metadata': request.form.get('client_metadata'),
        'wallet_issuer': request.form.get('wallet_issuer'),
        'state': request.form.get('state'),
        'authorization_details': request.form.get('authorization_details')
    })
    request_uri = 'urn:ietf:params:oauth:request_uri:' + str(uuid.uuid1())
    red.setex(request_uri, 50, json.dumps(request_uri_data))
    endpoint_response = {
        'request_uri': request_uri,
        'expires_in': 50
    }
    headers = {
        'Cache-Control': 'no-store',
        'Content-Type': 'application/json'
    }
    return Response(response=json.dumps(endpoint_response), headers=headers)


# IDP login for authorization code flow
def issuer_authorize_login(issuer_id):
    red = current_app.config["REDIS"]
    if request.method == 'GET':
        session['login'] = False
        session['test'] = False
        return render_template('issuer_oidc/authorize.html', url = '/issuer/' + issuer_id + '/authorize/login')
    if not red.get(request.form['test']):
        flash('Wrong test name', 'danger')
        #return redirect('/issuer/' + issuer_id + '/authorize/login') 
    session['login'] = True
    session['test'] = request.form['test']
    return redirect('/issuer/' + issuer_id + '/authorize?test=' + session['test']) 


# PID login for authorization code flow
def issuer_authorize_pid(issuer_id):
    red = current_app.config["REDIS"]
    state = request.form['state']
    code_data = json.loads(red.get(state).decode())
    # Code creation
    code = str(uuid.uuid1()) #+ '.' + str(uuid.uuid1()) + '.' + str(uuid.uuid1())
    red.setex(code, GRANT_LIFE, json.dumps(code_data))
    resp = {'code': code}
    if code_data['state']:
        resp['state'] = code_data['state']
    redirect_uri = code_data['redirect_uri']
    session.clear()
    return redirect(redirect_uri + '?' + urlencode(resp))


# authorization code endpoint
def issuer_authorize(issuer_id):
    red = current_app.config["REDIS"]
    mode = current_app.config["MODE"]
    
    # setup webhook_data for Error event
    webhook_data = {
        'event': 'ERROR',
        'issuer_id': issuer_id,
    }
    
    issuer = Issuer.query.filter(Issuer.application_api_issuer_id == webhook_data.get('issuer_id')).one_or_none()

    # test if a standalone AS is used
    if issuer.authorization_server and int(issuer.draft) >= 13:
        logging.error('wrong authorization endpoint used')
        return jsonify({
                    'error': 'invalid_request',
                    'error_description': 'invalid authorization server'
                }), 403
    
    # user not logged
    if not session.get('login'):
        logging.info('User is not logged')
        
        # Push Authorization Request
        if request_uri := request.args.get('request_uri'):
            try:
                request_uri_data = json.loads(red.get(request_uri).decode())   
            except Exception:
                logging.warning('redirect uri failed')
                return jsonify({
                    'error': 'invalid_request',
                    'error_description': 'request is expired'
                }), 403
            client_id = request_uri_data.get('client_id')
            issuer_state = request_uri_data.get('issuer_state')
            redirect_uri = request_uri_data.get('redirect_uri')
            response_type = request_uri_data.get('response_type')
            scope = request_uri_data.get('scope')
            nonce = request_uri_data.get('nonce')
            code_challenge = request_uri_data.get('code_challenge')
            code_challenge_method = request_uri_data.get('code_challenge_method')
            client_metadata = request_uri_data.get('client_metadata')
            wallet_issuer = request_uri_data.get('wallet_issuer')
            state = request_uri_data.get('state')
            authorization_details = request_uri_data.get('authorization_details')
        
        # Standard Authorization code flow
        else:
            try:
                redirect_uri = request.args['redirect_uri']
            except Exception:
                return jsonify({
                    'error': 'access_denied',
                    'error_description': 'redirect_uri is missing'
                }), 403
            try:
                response_type = request.args['response_type']
            except Exception:
                return redirect(redirect_uri + '?' + authorization_error('invalid_request', 'response_type is missing', None, red, state))
            try:
                scope = request.args['scope']
            except Exception:
                return redirect(redirect_uri + '?' + authorization_error('invalid_request', 'scope is missing', None, red, state))
            nonce = request.args.get('nonce')
            client_id = request.args.get('client_id')
            scope = request.args.get('scope')
            code_challenge = request.args.get('code_challenge')
            code_challenge_method = request.args.get('code_challenge_method')
            client_metadata = request.args.get('client_metadata')
            wallet_issuer = request.args.get('wallet_issuer')
            state = request.args.get('state')  # wallet state
            issuer_state = request.args.get('issuer_state') 
            authorization_details = request.args.get('authorization_details')
        
        logging.info('client_id of the wallet = %s', client_id)
        logging.info('redirect_uri = %s', redirect_uri)
        logging.info('code_challenge = %s', code_challenge)
        logging.info('client_metadata = %s ', client_metadata)
        logging.info('wallet_issuer = %s ', wallet_issuer)
        logging.info('authorization details = %s', authorization_details)
        logging.info('scope = %s', scope)
        if response_type != 'code':
            return redirect(redirect_uri + '?' + authorization_error('invalid_response_type', 'response_type not supported', None, red, state))
        
        # redirect user to login/password screen or redirect to VP request
        code_data = {
            'client_id': client_id,
            'scope': scope,
            'nonce': nonce,
            'authorization_details': authorization_details,
            'redirect_uri': redirect_uri,
            'issuer_id': issuer_id,
            'issuer_state': issuer_state,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': code_challenge_method,
        }
        session['code_data'] = code_data
        # redirect user to login/password screen
        if issuer_state != 'pid_authentication':
            return redirect('/issuer/' + issuer_id + '/authorize/login')
        
        # redirect user to VP request to get a PID
        else:
            # fetch credential.
            issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
            issuer_profile = profile[issuer_data['profile']]
            vc_list = issuer_profile['credential_configurations_supported'].keys()
            for vc in vc_list:
                if issuer_profile['credential_configurations_supported'][vc]['scope'] == session['code_data']['scope']:
                    break
            try:
                f = open('./verifiable_credentials/' + vc + '.jsonld', 'r')
            except Exception:
                # for vc+sd-jwt 
                try:
                    f = open('./verifiable_credentials/' + vc + '.json', 'r')
                except Exception:
                    logging.error('file not found')
                    return redirect(redirect_uri + '?' + authorization_error('invalid_request', 'VC not found', None, red, state))
            credential = json.loads(f.read())
            if client_metadata:
                wallet_authorization_endpoint = json.loads(client_metadata)['authorization_endpoint']
            elif wallet_issuer:
                resp = requests.get(wallet_issuer + '/.well-known/openid-configuration')
                wallet_authorization_endpoint = resp.json()['authorization_endpoint']
            else:
                logging.error('no wallet metadata')
                return redirect(redirect_uri + '?' + authorization_error('invalid_request', 'Wallet authorization endpoint not found', None, red, state))
            
            with open('presentation_definition_for_PID.json', 'r') as f:
                presentation_definition = json.loads(f.read())
            VP_request = {
                'aud': 'https://self-issued.me/v2',
                'client_id': 'did:web:talao.co',
                'client_id_scheme': 'redirect_uri',
                'exp': 1829170402,
                'iss': 'did:web:talao.co',
                'nonce': '5381697f-8c86-11ef-9061-0a1628958560',
                'response_mode': 'direct_post',
                'response_type': 'vp_token',
                'response_uri': mode.server + 'issuer/' + issuer_id + '/authorize/pid',
                'state': str(uuid.uuid1()),
                'presentation_definition': presentation_definition
            }
            code_data['vc'] = {vc: credential}
            code_data['credential_type'] = [vc]
            red.setex(VP_request['state'], 10000, json.dumps(code_data))
            return redirect(wallet_authorization_endpoint + '?' + urlencode(VP_request))
    
    # return from login/password screen
    logging.info('user is logged')
    session['login'] = False
    test = request.args.get('test')
    try:
        """
        issuer initiated authorization code flow with QR code
        """
        offer_data = json.loads(red.get(test).decode())
    except Exception:
        """ 
        wallet initiated authorization code flow -> create offer_data from file as it is needed for web wallet tests
        
        """
        # fetch credential
        issuer_data = json.loads(db_api.read_oidc4vc_issuer(issuer_id))
        issuer_profile = profile[issuer_data['profile']]
        vc_list = issuer_profile['credential_configurations_supported'].keys()
        for vc in vc_list:
            if issuer_profile['credential_configurations_supported'][vc]['scope'] == session['code_data']['scope']:
                break
        try:
            f = open('./verifiable_credentials/' + vc + '.jsonld', 'r')
        except Exception:
            # for vc+sd-jwt 
            try:
                f = open('./verifiable_credentials/' + vc + '.json', 'r')
            except Exception:
                logging.error('file not found')
                return redirect(redirect_uri + '?' + authorization_error('invalid_request', 'VC not found', None, red, state))
        credential = json.loads(f.read())
        offer_data = {
            'vc': {vc: credential},
            'credential_type': [vc]
        }
    
    # update code data with credential value   
    vc = offer_data['vc']
    try:
        session['code_data']['vc'] = vc
        session['code_data']['credential_type'] = offer_data['credential_type']
    except Exception:
        redirect_uri = session['code_data']['redirect_uri']
        logging.error('code_data key error oidc_vci 612')
        return redirect(redirect_uri + '?' + authorization_error('invalid_request', 'Session expired', None, red, state))

    # Code creation
    code = str(uuid.uuid1()) #+ '.' + str(uuid.uuid1()) + '.' + str(uuid.uuid1())
    red.setex(code, GRANT_LIFE, json.dumps(session['code_data']))
    resp = {'code': code}
    if session['code_data']['state']:
        resp['state'] = session['code_data']['state']
    redirect_uri = session['code_data']['redirect_uri']
    session.clear()
    return redirect(redirect_uri + '?' + urlencode(resp))


# nonce endpoint
def issuer_nonce():
    red = current_app.config["REDIS"]
    """
    https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#name-nonce-endpoint
    """
    nonce = str(uuid.uuid1())
    logging.info('Call of the nonce endpoint, nonce = %s', nonce)
    endpoint_response = {'c_nonce': nonce}
    red.setex(nonce, 60,'nonce')
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(endpoint_response), headers=headers)


# token endpoint
def issuer_token(issuer_id):
    red = current_app.config["REDIS"]
    mode = current_app.config["MODE"]
    
    # setup webhook_data for Error event
    webhook_data = {
        'event': 'ERROR',
        'issuer_id': issuer_id,
    }
    
    """
    token endpoint: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
    DPoP: https://datatracker.ietf.org/doc/rfc9449/
    """

    logging.info('token endoint header %s', request.headers)
    logging.info('token endoint form %s', json.dumps(request.form, indent=4))
    issuer = Issuer.query.filter(Issuer.application_api_issuer_id == issuer_id).one_or_none()    
    if not issuer:
        return Response(**manage_error('invalid_request', 'issuer not found', red, mode, webhook_data=webhook_data))
    
    # display DPoP
    if request.headers.get('DPoP'):
        try:
            DPoP_header = oidc4vc.get_header_from_token(request.headers.get('DPoP'))
            DPoP_payload = oidc4vc.get_payload_from_token(request.headers.get('DPoP'))
            logging.info('DPoP header = %s', json.dumps(DPoP_header, indent=4))
            logging.info('DPoP payload = %s', json.dumps(DPoP_payload, indent=4))
        except Exception as e:
            return Response(**manage_error('invalid_request', 'DPoP is incorrect ' + str(e), red, mode,webhook_data=webhook_data))
    else:
        logging.info('No DPoP')
    
    # check grant type
    grant_type = request.form.get('grant_type')
    if not grant_type:
        return Response(**manage_error('invalid_request', 'Request format is incorrect, grant is missing', red, mode))

    if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code' and not request.form.get('pre-authorized_code'):
        return Response(**manage_error('invalid_request', 'Request format is incorrect, this grant type is not supported', red, mode))

    if grant_type == 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
        code = request.form.get('pre-authorized_code')
        if int(issuer.draft) >= 13:
            user_pin = request.form.get('tx_code')
        else:
            user_pin = request.form.get('user_pin')
    elif grant_type == 'authorization_code':
        code = request.form.get('code')
        user_pin = None
    else:
        return Response(**manage_error('invalid_request', 'Grant type not supported', red, mode, webhook_data=webhook_data))
    
    # get data from code and check code validity
    try:
        data = json.loads(red.get(code).decode())
        webhook_data['issuer_state'] = data.get('issuer_state')
    except Exception:
        return Response(**manage_error('access_denied', 'Grant code expired', red, mode, status=404, webhook_data=webhook_data))
    
    if grant_type == 'authorization_code' and not request.form.get('redirect_uri'):
        return Response(**manage_error('invalid_request', 'Request format is incorrect, redirect_uri is missing', red, mode, webhook_data=webhook_data))

    # display client_authentication method
    if request.headers.get('Oauth-Client-Attestation'):
        client_authentication_method = 'client_attestation'
    elif request.headers.get('Authorization'):
        client_authentication_method = 'client_secret_basic'
    elif request.form.get('client_id') and request.form.get('client_secret'):
        client_authentication_method = 'client_secret_post'
    elif request.form.get('client_id'):
        client_authentication_method = 'client_id'
    else:
        client_authentication_method = 'none'
    logging.info('client authentication method = %s', client_authentication_method)
    
    # Check content of client assertion and proof of possession (PoP)
    if client_authentication_method == 'client_attestation':
        try:
            # https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-04.html
            client_assertion = request.headers['Oauth-Client-Attestation']
            PoP = request.headers['Oauth-Client-Attestation-Pop']
            logging.info('OAuth-Client-Attestation = %s', client_assertion)
            logging.info('OAuth-Client-Attestation-PoP = %s', PoP)
            if request.form.get('client_id') != oidc4vc.get_payload_from_token(client_assertion).get('sub'):
                return Response(**manage_error('invalid_request', 'client_id does not match client assertion subject', red, mode,  webhook_data=webhook_data))
            if oidc4vc.get_payload_from_token(client_assertion).get('sub') != oidc4vc.get_payload_from_token(PoP).get('iss'):
                return Response(**manage_error('invalid_request', 'sub of client assertion does not match proof of possession iss', red, mode, webhook_data=webhook_data))
        except Exception:
            return Response(**manage_error('invalid_request', 'Headres is notr correct for client attestation', red, mode, webhook_data=webhook_data))

    # check PKCE
    if grant_type == 'authorization_code' and int(issuer.draft) >= 10:
        code_verifier = request.form.get('code_verifier')
        code_challenge_calculated = pkce.get_code_challenge(code_verifier)
        if code_challenge_calculated != data['code_challenge']:
            return Response(**manage_error('access_denied', 'Code verifier is incorrect', red, mode,status=404,  webhook_data=webhook_data))

    # check tx_code
    if data.get('user_pin_required') and not user_pin:
        return Response(**manage_error('invalid_request', 'User code is missing', red, mode, webhook_data=webhook_data))
    logging.info('user_pin = %s', data.get('user_pin'))
    if data.get('user_pin_required') and data.get('user_pin') not in [user_pin, str(user_pin)]:
        return Response(**manage_error('invalid_grant', 'User code is incorrect', red, mode,  status=404,  webhook_data=webhook_data))

    # token endpoint response
    access_token = str(uuid.uuid1())
    refresh_token = str(uuid.uuid1())
    vc = data.get('vc')
    endpoint_response = {
        'access_token': access_token,
        'token_type': 'bearer',
        'expires_in': ACCESS_TOKEN_LIFE,
        'refresh_token': refresh_token
    }
    
    # add nonce in token endpoint response
    if int(issuer.draft) <= 13:
        endpoint_response['c_nonce'] = str(uuid.uuid1())
        endpoint_response['c_nonce_expires_in'] = 1704466725
        red.setex(endpoint_response['c_nonce'], 600, 'nonce')
        
    # authorization_details in case of multiple VC of the same type
    authorization_details = []
    if int(issuer.draft) >= 13 and isinstance(vc, list):
        for vc_type in vc:
            types = vc_type['types']
            vc_list = vc_type['list']
            identifiers = [one_vc['identifier'] for one_vc in vc_list]
            authorization_details.append(
                {
                    'type': 'openid_credential',
                    'format': 'jwt_vc_json',
                    'credential_definition': {
                        'type': types
                    },
                    'credential_identifiers': identifiers,
                }
            )
        logging.info('token endpoint response with authorization details')
        endpoint_response['authorization_details'] = authorization_details

    access_token_data = {
        'expires_at': datetime.timestamp(datetime.now()) + ACCESS_TOKEN_LIFE,
        'authorization_details': authorization_details,
        'client_id': request.form.get('client_id'),
        'scope': request.form.get('scope')
    }
    access_token_data.update(endpoint_response)
    access_token_data.update(data)
    logging.info('token endpoint response = %s', json.dumps(endpoint_response, indent=4))
    red.setex(access_token, ACCESS_TOKEN_LIFE, json.dumps(access_token_data))
    
    # send event to application webhook
    webhook_url = issuer.webhook_url    
    webhook_data = {
            'event': 'ACCESS_TOKEN_SENT',
            'issuer_id': issuer_id,
            'access_token': access_token,
            'state': data['issuer_state'],
    }
    push_to_webhook(webhook_url, webhook_data)
    
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(endpoint_response), headers=headers)


# credential endpoint
async def issuer_credential(issuer_id):
    red = current_app.config["REDIS"]
    mode = current_app.config["MODE"]
    logging.info('credential endoint header %s', request.headers)
    logging.info('credential endpoint request %s', json.dumps(request.json, indent=4))
    
    issuer = Issuer.query.filter(Issuer.application_api_issuer_id == issuer_id).one_or_none()    
    if not issuer:
        return Response(**manage_error('invalid_request', 'issuer not found', red, mode))
    
    # setup webhook_data for Error event
    webhook_data = {
        'event': 'ERROR',
        'issuer_id': issuer_id,
    }
    # DPoP
    if request.headers.get('DPoP'):
        try:
            DPoP_header = oidc4vc.get_header_from_token(request.headers.get('DPoP'))
            DPoP_payload = oidc4vc.get_payload_from_token(request.headers.get('DPoP'))
            logging.info('DPoP header = %s', json.dumps(DPoP_header, indent=4))
            logging.info('DPoP payload = %s', json.dumps(DPoP_payload, indent=4))
        except Exception as e:
            return Response(**manage_error('invalid_request', 'DPoP is incorrect ' + str(e), red, mode, webhook_data=webhook_data))
    else:
        logging.info('No DPoP')
        
    # Check access token
    try:
        access_token = request.headers['Authorization'].split()[1]
    except Exception:
        return Response(**manage_error('invalid_token', 'Access token not passed in request header', red, mode, webhook_data=webhook_data))
    
    # Get data"
    try:
        access_token_data = json.loads(red.get(access_token).decode())
        issuer_metadata = access_token_data.get("issuer_metadata")
    except Exception:
        return Response(**manage_error('invalid_token', 'Access token expired', red, mode,webhook_data=webhook_data))
    
    # setup issuer_state in webhook_data
    webhook_data['issuer_state'] = access_token_data.get('issuer_state')
    
    # Check request format
    try:
        result = request.json
    except Exception:
        return Response(**manage_error('invalid_request', 'Invalid request format', red, mode, webhook_data=webhook_data))

    # check vc format and credential_configuration_id
    vc_format = result.get('format')
    credential_configuration_id = None
    logging.info('format in credential request = %s', vc_format)
    if vc_format and vc_format not in ['ldp_vc', 'dc+sd-jwt', 'vc+sd-jwt']:
        return Response(**manage_error('unsupported_credential_format', 'Invalid VC format: ' + vc_format, red, mode, webhook_data=webhook_data))
    
    if int(issuer.draft) in [13, 14]:
        if result.get('format') in ['dc+sd-jwt', 'vc+sd-jwt'] and not result.get('vct'):
            return Response(**manage_error('invalid_request', 'Invalid request format, vct is missing for vc+sd-jwt format', red, mode, webhook_data=webhook_data))
        elif result.get('format') in ['dc+sd-jwt', 'vc+sd-jwt']:
            pass
        else:
            try:
                credential_definition = result['credential_definition']
                type = credential_definition['type'] # to check if it exists
                context = credential_definition['@context'] # to check if it exists
            except Exception:
                return Response(**manage_error('invalid_request', 'Invalid request format, type or @context is missing for ldp_vc', red, mode, webhook_data=webhook_data))
    
    elif int(issuer.draft) >= 15:
        if vc_format:
            return Response(**manage_error('invalid_request', 'Invalid request format, format is no more supported', red, mode, webhook_data=webhook_data))
        credential_configuration_id = result.get('credential_configuration_id')
        
    # check types for draft <13
    if int(issuer.draft) < 13 and not result.get('types'):
        return Response(**manage_error('unsupported_credential_format', 'Invalid VC format, types is missing', red, mode, webhook_data=webhook_data))

    # check proof if it exists depending on type of proof
    wallet_identifier = 'did'
    if proof := result.get('proof'):
        proof_type = proof['proof_type']
        if proof_type == 'jwt':
            jwt_proof = proof.get('jwt')
            proof_header = oidc4vc.get_header_from_token(jwt_proof)
            proof_payload = oidc4vc.get_payload_from_token(jwt_proof)
            logging.info('Proof header = %s', json.dumps(proof_header, indent=4))
            logging.info('Proof payload = %s', json.dumps(proof_payload, indent=4))
            if not proof_payload.get('nonce'):
                return Response(**manage_error('invalid_proof', 'c_nonce is missing', red, mode, status=403, webhook_data=webhook_data))
            
            try:
                oidc4vc.verif_token(jwt_proof)
                logging.info('proof is validated')
            except ValueError as e:
                logging.error(f"Proof verification failed: {e}")
                return Response(**manage_error('invalid_proof', 'Proof of key ownership, signature verification error: ' + str(e), red, mode, status=403))
            
            if not red.get(proof_payload['nonce']):
                logging.error('nonce does not exist')
            else:
                logging.info('nonce exists')
            
            if proof_header.get('jwk'): 
                wallet_jwk = proof_header.get('jwk')
                wallet_identifier = 'jwk'
                wallet_did = access_token_data.get('client_id')
            else:
                wallet_identifier = 'did'
                wallet_jwk = oidc4vc.resolve_did(proof_header.get('kid'))
                wallet_did = proof_header.get('kid').split("#")[0]

            if access_token_data.get('client_id') and proof_payload.get("iss"):
                if proof_payload.get("iss") != access_token_data.get('client_id'):
                    logging.error('iss %s of proof of key is different from client_id %s', proof_payload.get("iss") ,access_token_data.get('client_id') )
                    return Response(**manage_error('invalid_proof', 'iss of proof of key is different from client_id', red, mode, webhook_data=webhook_data))
        
        elif proof_type == 'ldp_vp':
            wallet_identifier = 'did'
            wallet_jwk = None
            proof = result['proof']['ldp_vp']
            proof = json.dumps(proof) if isinstance(proof, dict) else proof
            proof_check = await didkit.verify_presentation(proof, '{}')
            wallet_did = json.loads(proof).get('holder')
            logging.info('ldp_vp proof check  = %s', proof_check)
            if access_token_data.get("client_id") and wallet_did and wallet_did != access_token_data.get("client_id"):
                logging.warning('iss %s of proof of key is different from client_id %s', wallet_did, access_token_data.get("client_id") )
                return Response(**manage_error('invalid_proof', 'iss of proof of key is different from client_id in token request', red, mode, webhook_data=webhook_data))
        else:
            return Response(**manage_error('invalid_proof', 'Proof type not supported', red, mode))
    else:
        logging.warning('No proof available -> Bearer credential, wallet_did = client_id')
        wallet_jwk = None
        if vc_format == 'ldp_vc':
            return Response(**manage_error('invalid_proof', 'No proof with ldp_vc format is not supported', red, mode))
        else:
            wallet_did = access_token_data.get("client_id")
        
    logging.info('wallet_did = %s', wallet_did)
    logging.info('wallet_identifier = %s', wallet_identifier)
    logging.info('wallet_jwk = %s', wallet_jwk)

    # Get credential requested
    credential_identifier = None # the credential identifier in the offer and issuer metadata
    if int(issuer.draft) >= 15: # path pointer
        credential_identifier = credential_configuration_id
        vc_format = issuer_metadata["credential_configurations_supported"][credential_identifier]["format"]
    
    elif int(issuer.draft) in [13, 14]:
        credentials_supported_list = list(issuer_metadata['credential_configurations_supported'].keys())
        for vc in credentials_supported_list:
            if issuer_metadata['credential_configurations_supported'][vc]['vct'] == result.get('vct'):
                credential_identifier = vc
                break
        else:
            try:
                vc_type = result['credential_definition'].get('type')
            except Exception:
                logging.error("credential definition does not exist, wrong request format")
                return Response(**manage_error('invalid_request', 'credential definition not found', red, mode, webhook_data=webhook_data))
            vc_type.sort()
            for vc in credentials_supported_list:
                issuer_metadata['credential_configurations_supported'][vc]['credential_definition']['type'].sort()
                if issuer_metadata['credential_configurations_supported'][vc]['credential_definition']['type'] == vc_type:
                    credential_identifier = vc
                    break
    
    elif int(issuer.draft) == 11:
        credentials_supported = issuer_metadata['credentials_supported']
        if vc_format == 'vc+sd-jwt' and result.get('vct'):  
            for vc in credentials_supported:
                if vc['vct'] == result.get('vct'):
                    credential_identifier = vc
                    break
        else:
            types = result.get('types')
            types.sort()
            for vc in credentials_supported:
                vc['types'].sort()
                if vc['types'] == types:
                    credential_identifier = vc['id']
                    break
                
    logging.info('credential type = %s', credential_identifier)
    
    if not credential_identifier:
        return Response(**manage_error('unsupported_credential_type', 'VC type not found', red, mode, webhook_data=webhook_data))
    
    logging.info('Only one VC of the same type = %s and format = %s', credential_identifier, vc_format)
    credential_payload = access_token_data['vc'][credential_identifier]
    key_row = Credential.query.filter(Credential.credential_id == issuer.credential_id).first()
    
    # sign_credential(credential, wallet_did, issuer_id, c_nonce, format, issuer, mode, duration=365, wallet_jwk=None, wallet_identifier=None):
    if vc_format in ['vc+sd-jwt', 'dc+sd-jwt']:
        
        # update SD-JWT credential with vct and integrity from Registry
        registry_row = VCTRegistry.query.filter(VCTRegistry.name == credential_identifier).one_or_none()
        credential_payload["vct"] = registry_row.vct
        credential_payload["vct#integrity"] = registry_row.integrity
        
        # Status list support
        if issuer.status_list:
            credential_payload['status'] = {
                'status_list': {
                    'idx': randint(0, 99999),
                    'uri': mode.server + 'issuer/statuslist/1'
                }
            }
        
        # update of iss and x509 certificate use
        if issuer.issuer_urn == "url":
            x5c = issuer.sign_with_certificate  # True or False
            iss = access_token_data.get('credential_issuer')
        else: # issuer.issuer_urn == "did":
            x5c = False
            iss = key_row.did
        
        # get user account for qualified sigature
        user_id = issuer.user_id
        user = User.query.get_or_404(user_id)
        account = user.qtsp_account()
        
        # def sign_sd_jwt(unsecured, credential_row, account, iss, wallet_jwk, wallet_did, draft, wallet_identifier="jwk", duration=365*24*60*60, x5c=False):
        credential_signed = oidc4vc.sign_sd_jwt(credential_payload, key_row, account, iss, wallet_jwk, wallet_did, issuer.draft, wallet_identifier, x5c=x5c)
    
    else: #JSON-LD support
        credential_signed = await sign_jsonld_credential(
            credential_payload,
            wallet_did,
            issuer_id,
            access_token_data.get('c_nonce', 'nonce'),
            vc_format,
            mode.server + 'issuer/' + issuer_id,  # issuer
            mode,
            wallet_jwk=wallet_jwk,
            wallet_identifier=wallet_identifier,
            draft=int(issuer.draft) 
        )
    logging.info('credential signed sent to wallet = %s', credential_signed)
    if not credential_signed:
        return Response(**manage_error('internal_error', 'Credential signing error', red, mode,  webhook_data=webhook_data))

    # Transfer VC
    c_nonce = str(uuid.uuid1())
    if int(issuer.draft) >= 15:
        payload = {
            "credentials": [
                {
                    "credential":  credential_signed
                }
            ]
        }
    else:
        payload = {
            'credential': credential_signed,  # string or json depending on the format
            'c_nonce': c_nonce,
            'c_nonce_expires_in': C_NONCE_LIFE,
        }
    
    if int(issuer.draft) < 13:
        payload.update({'format': vc_format})
    
    # update nonce in access token for next VC request
    access_token_data['c_nonce'] = c_nonce
    red.setex(access_token, ACCESS_TOKEN_LIFE, json.dumps(access_token_data))

    # send event to application webhook
    webhook_data = {
            'event': 'CREDENTIAL_SENT',
            'issuer_id': issuer_id,
            'issuer_state': access_token_data['issuer_state'],
            'credential': credential_signed
    }
    push_to_webhook(issuer.webhook_url, webhook_data)
        
    # send VC to wallet
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return Response(response=json.dumps(payload), headers=headers)


async def sign_jsonld_credential(credential, wallet_did, issuer_did, duration, issuer_vm, issuer_key):
    logging.info('wallet did = %s', wallet_did)
    if wallet_did:
        credential['credentialSubject']['id'] = wallet_did
    else:
        credential['credentialSubject'].pop('id', None)
    credential['id'] = 'urn:uuid:' + str(uuid.uuid1())
    try:
        credential['issuer']['id'] = issuer_did
    except Exception:
        credential['issuer'] = issuer_did
    credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + 'Z'
    credential['expirationDate'] = (datetime.now() + timedelta(days=duration)).replace(microsecond=0).isoformat() + 'Z'
    # manage remote context
    old_context = credential['@context']
    new_context = ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/ed25519-2020/v1"]
    for url in old_context:
        if isinstance(url, dict):
            new_context.append(url)
        elif url not in  ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/ed25519-2020/v1"]:
            remote_file = requests.get(url, timeout=10).json()
            new_context.append(remote_file['@context'])
        else:
            pass
    credential["@context"] = new_context
    try:
        didkit_options = {
            'proofPurpose': 'assertionMethod',
            'verificationMethod': issuer_vm,
        }
        if issuer_vm in ["did:web:app.altme.io:issuer#key-1",  "did:web:talao.co#key-4"]:
            didkit_options["type"] = "Ed25519Signature2020"
        credential_signed = await didkit.issue_credential(
            json.dumps(credential),
            didkit_options.__str__().replace("'", '"'),
            issuer_key,
        )
        credential_signed_json = json.loads(credential_signed)
        # re set original @context
        credential_signed_json["@context"] = old_context
        credential_signed = json.dumps(credential_signed_json)
    except Exception as e:
        logging.warning('Didkit exception = %s', str(e))
        logging.warning('incorrect json_ld = %s', json.dumps(credential))
        return
    logging.info('VC signed with didkit')
    #result = await didkit.verify_credential(credential_signed, '{}')
    #logging.info('signature check with didkit = %s', result)
    credential_signed = json.loads(credential_signed)
    return credential_signed


def push_to_webhook(url, data):
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    try:
        requests.post(url, json=data, headers=headers, timeout=10)
    except Exception as e:
        logging.error("fail to send event as " + str(e))
        return
    return True
    