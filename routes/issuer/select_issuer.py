from flask import render_template, redirect, flash
from flask_login import login_required, current_user
from db_model import db, Issuer
import json

def init_app(app):
    app.add_url_rule('/issuer/select/<issuer_type>',  view_func=list_issuers, methods = ['GET'])
    app.add_url_rule('/issuer/delete/<issuer_type>/<issuer_id>',  view_func=delete_issuer, methods = ['POST'])
    app.add_url_rule('/issuer/go_to_production/<issuer_type>/<issuer_id>',  view_func=issuer_go_to_production, methods = ['GET'])
    app.add_url_rule('/issuer/go_to_sandbox/<issuer_type>/<issuer_id>',  view_func=issuer_go_to_sandbox, methods = ['GET'])


@login_required
def list_issuers(issuer_type):
    issuers = Issuer.query.filter(Issuer.user_id == current_user.id, Issuer.issuer_type == issuer_type).all()
    issuer_vct_names = {}
    for issuer in issuers:
        vct_names = []
        for vct_obj in json.loads(issuer.vc_type):
            vct_urn = vct_obj.get("urn")
            vct = VCTRegistry.query.filter(VCTRegistry.vct_urn == vct_urn).first()
            vct_names.append(vct.name)
        issuer_vct_names[issuer] = ", ".join(vct_names)
    return render_template(
        "issuer/select_issuer.html",
        issuers=issuers,
        issuer_type=issuer_type,
        user=current_user,
        issuer_vct_names=issuer_vct_names
    )


@login_required
def delete_issuer(issuer_type, issuer_id):
    issuer = Issuer.query.filter_by(id=issuer_id, user_id=current_user.id).first()
    if issuer:
        db.session.delete(issuer)
        db.session.commit()
        flash("✅  Issuer deleted.")
    else:
        flash("❌ Issuer not found.")
    return redirect("/issuer/select/" + issuer_type)


@login_required
def issuer_go_to_production(issuer_type, issuer_id):
    issuer = Issuer.query.filter_by(id=issuer_id, user_id=current_user.id).first()
    if issuer:
        issuer.issuer_type = "qualified"
        issuer.credential_id = None
        issuer.credential_id_for_encryption = None
        db.session.commit()
        flash("✅  Issuer transfered to production.")
    else:
        flash("❌ Issuer not found.")
    return redirect("/issuer/select/" + issuer_type)


@login_required
def issuer_go_to_sandbox(issuer_type, issuer_id):
    issuer = Issuer.query.filter_by(id=issuer_id, user_id=current_user.id).first()
    if issuer:
        issuer.issuer_type = "sandbox"
        issuer.credential_id = None
        issuer.credential_id_for_encryption = None
        db.session.commit()
        flash("✅  Issuer transfered to sandbox.")
    else:
        flash("❌ Issuer not found.")
    return redirect("/issuer/select/" + issuer_type)
