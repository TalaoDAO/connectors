from flask import render_template, redirect, flash
from flask_login import login_required, current_user
from db_model import db, Verifier
import json
from utils.kms import encrypt_json, decrypt_json

def init_app(app):
    app.add_url_rule('/verifier/select/<verifier_type>',  view_func=list_verifiers, methods = ['GET'])
    app.add_url_rule('/verifier/delete/<verifier_type>/<verifier_id>',  view_func=delete_verifier, methods = ['POST'])
    app.add_url_rule('/verifier/go_to_production/<verifier_type>/<verifier_id>',  view_func=go_to_production, methods = ['GET'])
    app.add_url_rule('/verifier/go_to_sandbox/<verifier_type>/<verifier_id>',  view_func=go_to_sandbox, methods = ['GET'])


@login_required
def list_verifiers(verifier_type):
    print(verifier_type)
    verifiers = Verifier.query.filter(Verifier.user_id == current_user.id, Verifier.verifier_type == verifier_type).all()

    print(verifiers)
    for v in verifiers:
        if v.test:
            v.test = False
            db.session.commit()
        try:
            v.application_api_json = decrypt_json(v.application_api)
        except Exception:
            v.application_api_json = {}
    return render_template(
        "verifier/select_verifier.html",
        verifiers=verifiers,
        verifier_type=verifier_type,
        user=current_user
    )


@login_required
def delete_verifier(verifier_type, verifier_id):
    verifier = Verifier.query.filter_by(id=verifier_id, user_id=current_user.id).first()
    if verifier:
        db.session.delete(verifier)
        db.session.commit()
        flash("✅  Verifier deleted.")
    else:
        flash("❌ Verifier not found.")
    return redirect("/verifier/select/" + verifier_type)


@login_required
def go_to_production(verifier_type, verifier_id):
    verifier = Verifier.query.filter_by(id=verifier_id, user_id=current_user.id).first()
    if verifier:
        verifier.verifier_type = "qualified"
        verifier.credential_id = None
        verifier.credential_id_for_encryption = None
        db.session.commit()
        flash("✅  Verifier transfered to production.")
    else:
        flash("❌ Verifier not found.")
    return redirect("/verifier/select/" + verifier_type)


@login_required
def go_to_sandbox(verifier_type, verifier_id):
    verifier = Verifier.query.filter_by(id=verifier_id, user_id=current_user.id).first()
    if verifier:
        verifier.verifier_type = "sandbox"
        verifier.credential_id = None
        verifier.credential_id_for_encryption = None
        db.session.commit()
        flash("✅  Verifier transfered to sandbox.")
    else:
        flash("❌ Verifier not found.")
    return redirect("/verifier/select/" + verifier_type)
