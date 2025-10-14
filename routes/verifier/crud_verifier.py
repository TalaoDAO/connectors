from flask import request, render_template, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from db_model import db, Verifier, default_verifier_request_key, Credential
import secrets
import json
import os
from utils.kms import encrypt_json, decrypt_json
from utils import oidc4vc
import logging

logging.basicConfig(level=logging.INFO)

def init_app(app):
    app.add_url_rule('/verifier/create/<verifier_type>', view_func=create_verifier, methods=["GET", "POST"])
    app.add_url_rule('/verifier/update/<verifier_type>/<verifier_id>', view_func=update_verifier, methods=["GET", "POST"])

def title(verifier_type, feature):
    if verifier_type == "sandbox" and feature == "create":
        return "Create a Verifier"
    elif verifier_type == "sandbox" and feature == "update":
        return "Update a Verifier"
    elif verifier_type == "qualified" and feature == "update":
        return "Update a Verifier for Production"
    elif verifier_type == "qualified" and feature == "create":
        return "Create a Verifier for Production"

    
def create_application_api():
    # Generate a 16-character hex string (8 bytes) as client_id
    mode = current_app.config["MODE"]
    return {
        "url": mode.server + "verifier/app",
        "verifier_id": secrets.token_hex(8),
        "verifier_secret": secrets.token_hex(32),
    }

def create_vp_formats():
    with open("vp_formats.json", "r") as f:
        vp_formats = json.load(f)
    return vp_formats

def calculate_client_id(draft, client_id_scheme, credential,mode):
    #https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html
    #https://openid.net/specs/openid-4-verifiable-presentations-1_0-22.html
    # https://openid.net/specs/openid-4-verifiable-presentations-1_0-29.html
    redirect_uri = mode.server + "verifier/wallet/callback"
    client_id = "redirect_uri"
    if int(draft) == 8 :
        if client_id_scheme == "did":
            client_id = credential.did
        elif client_id_scheme == "url":
            client_id = redirect_uri
    
    elif int(draft) == 18: # client_id_scheme added
        if client_id_scheme == "redirect_uri":
            client_id = redirect_uri
        elif client_id_scheme == "did":
            client_id = credential.did
    
    elif int(draft) == 20: # 
        if client_id_scheme == "x509_san_dns":
            client_id = oidc4vc.extract_first_san_dns_from_der_b64(credential.certificate)
        elif client_id_scheme == "redirect_uri":
            client_id = redirect_uri
        elif client_id_scheme == "verifier_attestation":
            client_id = oidc4vc.get_payload_from_token(credential.verifier_attestation)["sub"]
        elif client_id_scheme == "did":
            client_id = credential.did
            
    elif int(draft) ==  22: # no more client_id_scheme
        if client_id_scheme == "x509_san_dns":
            client_id = "x509_san_dns:" + oidc4vc.extract_first_san_dns_from_der_b64(credential.certificate)
        elif client_id_scheme == "redirect_uri":
            client_id =  "redirect_uri:" + redirect_uri
        elif client_id_scheme == "verifier_attestation":
            client_id = "verifier_attestation:" + oidc4vc.get_payload_from_token(credential.verifier_attestation)["sub"]
        elif client_id_scheme == "did":
            client_id = credential.did
    
    elif int(draft) >=  28:
        # no more client_id_scheme
        if client_id_scheme == "x509_san_dns":
            client_id = "x509_san_dns:" + oidc4vc.extract_first_san_dns_from_der_b64(credential.certificate)
        elif client_id_scheme == "redirect_uri":
            client_id = "redirect_uri:" + redirect_uri
        elif client_id_scheme == "verifier_attestation":
            client_id = "verifier_attestation:" + oidc4vc.get_payload_from_token(credential.verifier_attestation)["sub"]
        elif client_id_scheme == "decentralized_identifier":
            client_id = "decentralized_identifier:" + credential.did
    return client_id
    


@login_required
def create_verifier(verifier_type):
    mode = current_app.config["MODE"]
    credentials = Credential.query.filter(Credential.user_id.in_([1, current_user.id])).filter(Credential.credential_type == verifier_type).filter(Credential.use == "sign").all()
    encryption_credentials = Credential.query.filter(Credential.user_id.in_([1, current_user.id])).filter(Credential.use == "enc").filter(Credential.credential_type == verifier_type).all()
    if request.method == "GET":
        return render_template(
            "verifier/crud_verifier.html",
            user=current_user,
            credentials=credentials,
            encryption_credentials=encryption_credentials,
            name="verifier-" + str(secrets.randbelow(999999)),
            verifier_type=verifier_type,
            draft="20",
            button="Create Verifier",
            api=create_application_api(),
            verifier_metadata={"vp_formats": create_vp_formats()},
            presentation={},
            title=title(verifier_type, "create")

        )

    def parse_json_field(raw, field_name, expect_list=False) -> dict:
        if not raw:
            return None
        try:
            val = json.loads(raw)
            if expect_list and not isinstance(val, list):
                raise ValueError(f"{field_name} must be a JSON array.")
            if not expect_list and isinstance(val, list):
                raise ValueError(f"{field_name} must be a JSON object or string, not an array.")
            return val
        except Exception as e:
            if mode.debug:
                flash(f"❌ Invalid {field_name}: {e}")
            else:
                flash(f"❌ Invalid {field_name}")
            raise
        
    # POST request
    name = request.form.get("name")
    description = request.form.get("description")
    client_id_scheme = request.form.get("client_id_scheme")
    presentation_format = request.form.get("presentation_format")
    response_mode = request.form.get("response_mode", "direct_post")
    draft = request.form.get("draft")
    response_type = request.form.get("response_type")
    prefix = request.form.get("prefix")
    api = request.form.get('api').replace("'", '"')
    credential_id = request.form.get("credential_id")
    credential_id_for_encryption = request.form.get("credential_id_for_encryption")
    response_encryption = request.form.get("response_encryption") == "True"
    response_redirect_uri = request.form.get("response_redirect_uri")
    raw_info = request.form.get("verifier_info", "").strip() # json
    raw_metadata = request.form.get("verifier_metadata", "").strip() # json
    raw_presentation = request.form.get("presentation", "").strip() # json"
    log = request.form.get("log") == "True"
    webhook_url = request.form.get("webhook_url")
    webhook_api_key = request.form.get("webhook_api_key")
    try:
        info = parse_json_field(raw_info, "Verifier Info JSON Array", expect_list = True)
        metadata = parse_json_field(raw_metadata, "Verifier Metadata JSON ")
        presentation = parse_json_field(raw_presentation, "Presentation JSON in PEX DCQL")
    except Exception:
        # flash already set in parse_json_field
        # re-render with previously entered values
        return render_template(
            "verifier/crud_verifier.html",
            user=current_user,
            description=description,
            client_id_scheme=client_id_scheme,
            presentation=raw_presentation,
            presentation_format=presentation_format,
            verifier_metadata={"vp_formats": create_vp_formats()},
            verifier_info=raw_info,
            response_type=response_type,
            response_encryption=response_encryption,
            credentials=credentials,
            draft=draft,
            credential_id=credential_id,
            credential_id_for_encryption=credential_id_for_encryption,
            name=name,
            response_redirect_uri=response_redirect_uri,
            response_mode=response_mode,
            encryption_credentials=encryption_credentials,
            verifier_type=verifier_type,
            log=log,
            button="Create Verifier",
            api=api,
            title=title(verifier_type, "create"),
            webhook_url=webhook_url,
            webhook_api_key=webhook_api_key
        )
    
    if current_user.is_authenticated:
        # Create Verifier object
        verifier = Verifier(
            user_id=current_user.id,
            name=name,
            description=description,
            verifier_type=verifier_type,
            client_id_scheme=client_id_scheme,
            presentation_format=presentation_format,
            response_encryption=response_encryption,
            response_type=response_type,
            response_mode=response_mode,
            credential_id=credential_id,
            credential_id_for_encryption=credential_id_for_encryption,
            verifier_info=json.dumps(info),
            presentation=json.dumps(presentation),
            verifier_metadata=json.dumps(metadata),
            application_api=encrypt_json(json.loads(api)),
            application_api_verifier_id=json.loads(api).get("verifier_id"),
            draft=draft,
            prefix=prefix,
            response_redirect_uri=response_redirect_uri,
            log=log,
            webhook_url=webhook_url,
            webhook_api_key=webhook_api_key
        )
        credential = Credential.query.filter(Credential.credential_id == credential_id).first()
        
        if verifier.client_id_scheme in ["decentralized_identifier", "did"]:
            if not credential.did or not credential.verification_method:
                flash("❌ This Credential ID does not support DIDs.")
                return redirect("/verifier/select/" + verifier_type)
        elif verifier.client_id_scheme == "verifier_attestation" and not credential.verifier_attestation:
            flash("❌ This Credential ID does not support verifier attestation.")
            return redirect("/verifier/select/" + verifier_type)
        elif verifier.client_id_scheme == "x509_san_dns" and not credential.x5c:
            flash("❌ This Credential ID does not support X509 certificates.")
            return redirect("/verifier/select/" + verifier_type)
        
        if response_encryption and response_mode == "direct_post":
            flash("❌ Encryption is not available for response_mode direct_post.")
            return redirect("/verifier/select/" + verifier_type)
        if response_encryption and not credential_id_for_encryption:
            flash("❌ The Credential ID does  not support encryption.")
            return redirect("/verifier/select/" + verifier_type)
        
        if presentation and presentation_format == "presentation_exchange":
            if "id" not in presentation or "input_descriptors" not in presentation: 
                flash("❌ The presentation object is not correctly set .")
                return redirect("/verifier/select/" + verifier_type)
        
        if client_id := calculate_client_id(draft, client_id_scheme, credential, mode):
            verifier.client_id = client_id
        else:
            flash("❌ client_id error.")
            return redirect("/verifier/create/" + verifier_type)
        try:
            db.session.add(verifier)
            db.session.commit()
        except Exception as e:
            if mode.debug:
                flash(f"❌ {e}")
            else:
                flash("❌ Server error")
        if not presentation:
            flash("🔔 Verifier created but no presentation has been saved. Fill the API.")
        elif not webhook_url:
            flash("🔔 Verifier created but no webhook has been saved. Fill the API.")
        else:
            flash("✅ Verifier created successfully.")
        return redirect("/verifier/select/" + verifier_type)
    else:
        flash("✅ Register to Create a Verifier.")
        return redirect("/register")




@login_required
def update_verifier(verifier_type, verifier_id):
    mode = current_app.config["MODE"]
    credentials = Credential.query.filter(Credential.user_id.in_([1, current_user.id])).filter(Credential.credential_type == verifier_type).filter(Credential.use == "sign").all()
    encryption_credentials = Credential.query.filter(Credential.user_id.in_([1, current_user.id])).filter(Credential.use == "enc").filter(Credential.credential_type == verifier_type).all()
    verifier = Verifier.query.filter_by(id=verifier_id, user_id=current_user.id).first()
    api = decrypt_json(verifier.application_api)
    if request.method == "GET":
        return render_template(
            "verifier/crud_verifier.html",
            user=current_user,
            description=verifier.description,
            client_id_scheme=verifier.client_id_scheme,
            presentation=json.loads(verifier.presentation),
            presentation_format=verifier.presentation_format,
            verifier_metadata=json.loads(verifier.verifier_metadata),
            verifier_info=json.loads(verifier.verifier_info),
            response_encryption=verifier.response_encryption,
            credentials=credentials,
            draft=verifier.draft,
            response_type=verifier.response_type,
            credential_id=verifier.credential_id,
            credential_id_for_encryption=verifier.credential_id_for_encryption,
            name=verifier.name,
            response_redirect_uri=verifier.response_redirect_uri,
            response_mode=verifier.response_mode,
            encryption_credentials=encryption_credentials,
            verifier_type=verifier_type,
            button="Update Verifier",
            log=verifier.log,
            api=api,
            title=title(verifier_type, "update"),
            webhook_url=verifier.webhook_url,
            webhook_api_key=verifier.webhook_api_key
        )

    def parse_json_field(raw, field_name, expect_list=False) -> dict:
        if not raw:
            return None
        try:
            val = json.loads(raw)
            if expect_list and not isinstance(val, list):
                raise ValueError(f"{field_name} must be a JSON array.")
            if not expect_list and isinstance(val, list):
                raise ValueError(f"{field_name} must be a JSON object or string, not an array.")
            return val
        except Exception as e:
            if mode.debug:
                flash(f"❌ Invalid {field_name}")
            else:
                flash(f"❌ Invalid {field_name}: {e}")
            raise
        
    # POST request
    name = request.form.get("name")
    description = request.form.get("description")
    client_id_scheme = request.form.get("client_id_scheme")
    presentation_format = request.form.get("presentation_format")
    response_mode = request.form.get("response_mode", "direct_post")
    response_type = request.form.get("response_type")
    draft = request.form.get("draft")
    prefix = request.form.get("prefix")
    credential_id = request.form.get("credential_id")
    credential_id_for_encryption = request.form.get("credential_id_for_encryption")
    response_encryption = request.form.get("response_encryption") == "True"
    response_redirect_uri = request.form.get("response_redirect_uri")
    raw_info = request.form.get("verifier_info", "").strip() # json
    raw_metadata = request.form.get("verifier_metadata", "").strip() # json
    raw_presentation = request.form.get("presentation", "").strip() # json"
    log = request.form.get("log") == "True"
    api = request.form.get("api").replace("'", '"')
    webhook_url = request.form.get("webhook_url", "")
    webhook_api_key = request.form.get("webhook_api_key", "")
    
    try:
        info = parse_json_field(raw_info, "Verifier Info JSON Array", expect_list = True)
        metadata = parse_json_field(raw_metadata, "Verifier Metadata JSON ")
        presentation = parse_json_field(raw_presentation, "Presentation JSON in PEX DCQL")
        
        credential = Credential.query.filter(Credential.credential_id == credential_id).first()
        if client_id_scheme in ["decentralized_identifier", "did"]:
            if not credential.did or not credential.verification_method:
                flash("❌ This Credential ID does not support DIDs.")
                return redirect("/verifier/select/" + verifier_type)
        elif client_id_scheme == "verifier_attestation" and not credential.verifier_attestation:
            flash("❌ This Credential ID does not support verifier attestation.")
            return redirect("/verifier/select/" + verifier_type)
        elif client_id_scheme == "x509_san_dns" and not credential.x5c:
            flash("❌ This Credential ID does not support X509 certificates.")
            return redirect("/verifier/select/" + verifier_type)
        
        if response_encryption and response_mode == "direct_post":
            flash("❌ Encryption is not available for response_mode direct_post.")
            return redirect("/verifier/select/" + verifier_type)
        if response_encryption and not credential_id_for_encryption:
            flash("❌ The verifier has no encryption key.")
            return redirect("/verifier/select/" + verifier_type)
        
        if presentation and presentation_format == "presentation_exchange":
            if "id" not in presentation or "input_descriptors" not in presentation: 
                flash("❌ The presentation object is not correctly set .")
                return redirect("/verifier/select/" + verifier_type)
    
    except Exception:
        try:
            json.loads(raw_metadata)
        except Exception:
            raw_metadata = verifier.verifier_metadata
        try:
            json.loads(raw_info)
        except Exception:
            raw_info = verifier.verifier_info
        # flash already set in parse_json_field
        # re-render with previously entered values
        return render_template(
            "verifier/crud_verifier.html",
            user=current_user,
            description=description,
            client_id_scheme=client_id_scheme,
            presentation=json.loads(raw_presentation),
            presentation_format=presentation_format,
            verifier_metadata=json.loads(raw_metadata),
            verifier_info=json.loads(raw_info),
            response_encryption=response_encryption,
            credentials=credentials,
            draft=draft,
            response_type=response_type,
            credential_id=credential_id,
            credential_id_for_encryption=credential_id_for_encryption,
            name=name,
            response_redirect_uri=response_redirect_uri,
            response_mode=response_mode,
            encryption_credentials=encryption_credentials,
            verifier_type=verifier_type,
            button="Update Verifier",
            log=log,
            api=api,
            title=title(verifier_type, "update"),
            webhook_url=webhook_url,
            webhook_api_key=webhook_api_key
        )
    
    client_id = calculate_client_id(draft, client_id_scheme, credential, mode)
    verifier.client_id = client_id
    verifier.name = name
    verifier.description = description
    verifier.verifier_type = verifier_type
    verifier.client_id_scheme = client_id_scheme
    verifier.presentation_format = presentation_format
    verifier.response_encryption = response_encryption
    verifier.response_mode = response_mode
    verifier.response_type = response_type
    verifier.credential_id = credential_id
    verifier.credential_id_for_encryption = credential_id_for_encryption
    verifier.verifier_info = json.dumps(info)
    verifier.presentation = json.dumps(presentation)
    verifier.verifier_metadata = json.dumps(metadata)
    verifier.draft = draft
    verifier.response_type = response_type
    verifier.prefix = prefix
    verifier.response_redirect_uri = response_redirect_uri
    verifier.log = log
    verifier.webhook_url = webhook_url
    verifier.webhook_api_key = webhook_api_key
    try:
        db.session.commit()
        if not presentation:
            flash("🔔 Verifier updated but no presentation has been saved. Fill the API.")
        elif not webhook_url:
            flash("🔔 Verifier updated but no webhook has been saved. Fill the API.")
        else:
            flash("✅ Verifier updates successfully.")
        return redirect("/verifier/select/" + verifier_type)
    except Exception as e:
        if mode.debug:
            flash("❌ Server error, impossible to update the Verifier.  %s" + str(e))
        else:
            flash("❌ Server error, impossible to update the Verifier.")
        return redirect("/verifier/select/" + verifier_type)
