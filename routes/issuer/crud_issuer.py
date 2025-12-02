
from flask import request, render_template, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from db_model import db, Issuer, Credential
import secrets
import json
import re
from kms_model import encrypt_json, decrypt_json


def init_app(app):
    app.add_url_rule('/issuer/create/<issuer_type>', view_func=create_issuer, methods=["GET", "POST"])
    app.add_url_rule('/issuer/update/<issuer_type>/<issuer_id>', view_func=update_issuer, methods=["GET", "POST"])


def title(issuer_type, feature):
    if issuer_type == "sandbox" and feature == "create":
        return "Create an Issuer for Sandbox"
    elif issuer_type == "sandbox" and feature == "update":
        return "Update a Sandbox Issuer"
    elif issuer_type == "qualified" and feature == "update":
        return "Update an Issuer for Production"
    elif issuer_type == "qualified" and feature == "create":
        return "Create an Issuer for Production"
    return "Issuer"


def create_application_api():
    mode = current_app.config["MODE"]
    issuer_id = secrets.token_hex(8)  # 16-char hex
    return {
        "url": mode.server + "issuer/app/credential-offer",
        "issuer_id": issuer_id,
        "issuer_secret": secrets.token_hex(32),
    }


def create_vp_formats():
    with open("vp_formats.json", "r") as f:
        return json.load(f)


# ----------------------- Helpers -----------------------

def parse_json_field(raw, field_name, expect_list=False):
    """Parse a JSON value. Optionally enforce list vs non-list."""
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
        flash(f"❌ Invalid {field_name}: {e}")
        raise


IDENT_RE = re.compile(r"^[A-Za-z0-9_-]+$")

def parse_vc_type_objects(raw: str, field_name: str) -> list[dict]:
    """
    Accept a JSON array of either strings (legacy) or objects with keys {urn, credential_identifier}.
    Normalize to a list of dicts {"urn": str, "credential_identifier": str}.
    Validate: urn non-empty; credential_identifier matches ^[A-Za-z0-9_-]+$ if present.
    Deduplicate by URN (last wins).
    """
    raw = (raw or "").strip()
    if not raw:
        return []
    try:
        val = json.loads(raw)
        if not isinstance(val, list):
            raise ValueError("VC Type must be a JSON array.")
        out = []
        for item in val:
            if isinstance(item, str):
                urn = item.strip()
                if not urn:
                    raise ValueError("URN cannot be empty.")
                out.append({"urn": urn, "credential_identifier": ""})
            elif isinstance(item, dict):
                urn = item.get("urn") or item.get("id") or item.get("vct") or item.get("vct_urn")
                if not urn or not isinstance(urn, str) or not urn.strip():
                    raise ValueError("Each item needs a non-empty 'urn' (or 'id'/'vct'/'vct_urn').")
                ci = item.get("credential_identifier", "")
                if ci is None:
                    ci = ""
                if not isinstance(ci, str):
                    raise ValueError("'credential_identifier' must be a string.")
                ci = ci.strip()
                if ci and not IDENT_RE.match(ci):
                    raise ValueError("credential_identifier must match ^[A-Za-z0-9_-]+$ (no spaces).")
                out.append({"urn": urn.strip(), "credential_identifier": ci})
            else:
                raise ValueError("Invalid VC Type item.")
        # Deduplicate by URN (last wins)
        dedup = {}
        for o in out:
            dedup[o["urn"]] = o
        return list(dedup.values())
    except Exception as e:
        flash(f"❌ Invalid {field_name}: {e}")
        raise


# ----------------------- Create -----------------------

@login_required
def create_issuer(issuer_type):
    credentials = (
        Credential.query
        .filter(Credential.user_id.in_([1, current_user.id]))
        .filter(Credential.credential_type == issuer_type)
        .filter(Credential.use == "sign")
        .all()
    )
    application_api_json = create_application_api()

    if request.method == "GET":
        return render_template(
            "issuer/crud_issuer.html",
            user=current_user,
            credentials=credentials,
            name="#" + str(secrets.randbelow(100000)),
            issuer_vc_type=[],  # DB will store array[ {urn, credential_identifier} ]
            issuer_type=issuer_type,
            issuer_urn="url",
            draft="13",
            sign_with_certificate=True,
            credential_offer_uri=True,
            grant_type="urn:ietf:params:oauth:grant-type:pre-authorized_code",
            tx_code_required=False,
            tx_code_description="Enter the code you received",
            tx_code_length="4",
            tx_code_input_mode="numeric",
            button="Create Issuer",
            application_api=encrypt_json(application_api_json),
            api=application_api_json,
            issuer_metadata={"vp_formats": create_vp_formats()},
            title=title(issuer_type, "create")
        )

    # POST
    name = request.form.get("name")
    webhook_url = request.form.get("webhook_url")
    description = request.form.get("description")
    draft = request.form.get("draft")
    prefix = request.form.get("prefix")
    application_api = request.form.get("application_api")
    credential_id = request.form.get("credential_id")
    raw_metadata = (request.form.get("issuer_metadata", "") or "").strip()
    log = request.form.get("log") == "True"
    grant_type = request.form.get("grant_type")
    tx_code_required = request.form.get("tx_code_required") == "True"
    tx_code_input_mode = request.form.get("tx_code_input_mode")
    tx_code_length = request.form.get("tx_code_length", "4")
    tx_code_description = request.form.get("tx_code_description")
    authorization_server = request.form.get("authorization_server")
    par = request.form.get("par") == "True"
    signed_metadata = request.form.get("signed_metadata") == "True"
    sign_with_certificate = request.form.get("sign_with_certificate") == "True"
    credential_offer_uri = request.form.get("credential_offer_uri") == "True"
    issuer_urn = request.form.get("issuer_urn")

    # Parse VC Types: store objects {urn, credential_identifier}
    try:
        vc_type_objs = parse_vc_type_objects(request.form.get("vc_type"), "VC Type list")
    except Exception:
        return redirect(request.path)

    # Parse issuer metadata (object or None)
    try:
        metadata = parse_json_field(raw_metadata, "Issuer Metadata JSON ")
    except Exception:
        # flash already set — re-render form
        return render_template(
            "issuer/crud_issuer.html",
            grant_type=grant_type,
            tx_code_required=tx_code_required,
            tx_code_input_mode=tx_code_input_mode,
            tx_code_length=tx_code_length,
            tx_code_description=tx_code_description,
            authorization_server=authorization_server,
            par=par,
            user=current_user,
            description=description,
            issuer_metadata={"vp_formats": create_vp_formats()},
            credentials=credentials,
            draft=draft,
            credential_id=credential_id,
            name=name,
            webhook_url=webhook_url,
            issuer_type=issuer_type,
            log=log,
            sign_with_certificate=sign_with_certificate,
            issuer_urn=issuer_urn,
            button="Create Issuer",
            api=decrypt_json(application_api) if application_api else {},
            application_api=application_api,
            signed_metadata=signed_metadata,
            credential_offer_uri=credential_offer_uri,
            title=title(issuer_type, "create")
        )

    if not current_user.is_authenticated:
        flash("✅ Register to Create a Issuer.")
        return redirect("/register")

    issuer = Issuer(
        user_id=current_user.id,
        grant_type=grant_type,
        name=name,
        webhook_url=webhook_url,
        description=description,
        issuer_type=issuer_type,
        credential_id=credential_id,
        sign_with_certificate=sign_with_certificate,
        issuer_metadata=json.dumps(metadata or {}),
        vc_type=json.dumps(vc_type_objs),  # store array[{urn, credential_identifier}]
        application_api=application_api,
        application_api_issuer_id=(decrypt_json(application_api) or {}).get("issuer_id") if application_api else None,
        draft=draft,
        prefix=prefix,
        log=log,
        tx_code_required=tx_code_required,
        tx_code_input_mode=tx_code_input_mode,
        tx_code_length=tx_code_length,
        tx_code_description=tx_code_description,
        authorization_server=authorization_server,
        par=par,
        issuer_urn=issuer_urn,
        signed_metadata=signed_metadata,
        credential_offer_uri=credential_offer_uri
    )
    db.session.add(issuer)
    db.session.commit()
    flash("✅ Issuer created successfully.")
    return redirect("/issuer/select/" + issuer_type)


# ----------------------- Update -----------------------

@login_required
def update_issuer(issuer_type, issuer_id):
    mode = current_app.config["MODE"]

    credentials = (
        Credential.query
        .filter(Credential.user_id.in_([1, current_user.id]))
        .filter(Credential.credential_type == issuer_type)
        .filter(Credential.use == "sign")
        .all()
    )
    issuer = Issuer.query.filter_by(id=issuer_id, user_id=current_user.id).first()
    api = decrypt_json(issuer.application_api) if issuer and issuer.application_api else {}

    if request.method == "GET":
        return render_template(
            "issuer/crud_issuer.html",
            user=current_user,
            grant_type=issuer.grant_type,
            description=issuer.description,
            issuer_metadata=json.loads(issuer.issuer_metadata or "{}"),
            issuer_vc_type=json.loads(issuer.vc_type or "[]"),  # array[object] or legacy array[str]
            credentials=credentials,
            draft=issuer.draft,
            credential_id=issuer.credential_id,
            name=issuer.name,
            webhook_url=issuer.webhook_url,
            issuer_type=issuer_type,
            button="Update Issuer",
            log=issuer.log,
            sign_with_certificate=issuer.sign_with_certificate,
            title=title(issuer_type, "update"),
            tx_code_required=issuer.tx_code_required,
            tx_code_input_mode=issuer.tx_code_input_mode,
            tx_code_length=issuer.tx_code_length,
            tx_code_description=issuer.tx_code_description,
            authorization_server=issuer.authorization_server,
            par=issuer.par,
            api=api,
            application_api=issuer.application_api,
            issuer_urn=issuer.issuer_urn,
            signed_metadata=issuer.signed_metadata,
            credential_offer_uri=issuer.credential_offer_uri,
            issuer_identifier=f'{mode.server}issuer/{issuer.application_api_issuer_id}'
        )

    # POST
    name = request.form.get("name")
    webhook_url = request.form.get("webhook_url")
    description = request.form.get("description")
    draft = request.form.get("draft")
    prefix = request.form.get("prefix")
    credential_id = request.form.get("credential_id")
    raw_metadata = (request.form.get("issuer_metadata", "") or "").strip()
    log = request.form.get("log") == "True"
    grant_type = request.form.get("grant_type")
    tx_code_required = request.form.get("tx_code_required") == "True"
    sign_with_certificate = request.form.get("sign_with_certificate") == "True"
    tx_code_input_mode = request.form.get("tx_code_input_mode")
    tx_code_length = request.form.get("tx_code_length")
    tx_code_description = request.form.get("tx_code_description")
    authorization_server = request.form.get("authorization_server")
    par = request.form.get("par") == "True"
    issuer_urn = request.form.get("issuer_urn")
    signed_metadata = request.form.get("signed_metadata") == "True"
    credential_offer_uri = request.form.get("credential_offer_uri") == "True"

    # VC Type: parse objects
    try:
        vc_type_objs = parse_vc_type_objects(request.form.get("vc_type"), "VC Type list")
    except Exception:
        return redirect(f"/issuer/update/{issuer_type}/{issuer_id}")

    # Parse issuer metadata
    try:
        metadata = parse_json_field(raw_metadata, "Issuer Metadata JSON ")
        _ = Credential.query.filter(Credential.credential_id == credential_id).first()
    except Exception:
        # Try to keep user's last good JSON if possible
        try:
            json.loads(raw_metadata)
        except Exception:
            raw_metadata = issuer.issuer_metadata
        return render_template(
            "issuer/crud_issuer.html",
            user=current_user,
            description=description,
            issuer_metadata=json.loads(raw_metadata or "{}"),
            credentials=credentials,
            sign_with_certificate=sign_with_certificate,
            draft=draft,
            name=name,
            webhook_url=webhook_url,
            issuer_type=issuer_type,
            button="Update Issuer",
            log=log,
            title=title(issuer_type, "update"),
            grant_type=grant_type,
            tx_code_required=tx_code_required,
            tx_code_input_mode=tx_code_input_mode,
            tx_code_length=tx_code_length,
            tx_code_description=tx_code_description,
            authorization_server=authorization_server,
            par=par,
            api=api,
            application_api=issuer.application_api,
            issuer_urn=issuer_urn,
            signed_metadata=signed_metadata,
            credential_offer_uri=credential_offer_uri,
            issuer_vc_type=vc_type_objs
        )

    # Apply updates
    issuer.name = name
    issuer.webhook_url = webhook_url
    issuer.description = description
    issuer.issuer_type = issuer_type
    issuer.credential_id = credential_id
    issuer.issuer_metadata = json.dumps(metadata or {})
    issuer.draft = draft
    issuer.prefix = prefix
    issuer.log = log
    issuer.grant_type = grant_type
    issuer.tx_code_required = tx_code_required
    issuer.tx_code_input_mode = tx_code_input_mode
    issuer.tx_code_length = tx_code_length
    issuer.tx_code_description = tx_code_description
    issuer.authorization_server = authorization_server
    issuer.par = par
    issuer.sign_with_certificate = sign_with_certificate
    issuer.issuer_urn = issuer_urn
    issuer.signed_metadata = signed_metadata
    issuer.credential_offer_uri = credential_offer_uri
    issuer.vc_type = json.dumps(vc_type_objs)

    db.session.commit()
    flash("✅ Issuer updated successfully.")
    return redirect("/issuer/select/" + issuer_type)
