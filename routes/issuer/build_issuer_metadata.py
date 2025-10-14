import json
import re
from typing import Any, Dict, List, Optional
from flask import current_app
from db_model import Issuer

# ---------- helpers ----------

def _draft_int(val) -> int:
    try:
        return int(val or 15)
    except Exception:
        return 15

def _fmt_for_draft(d: int) -> str:
    # sd-jwt format identifier switched in -15
    return "dc+sd-jwt" if d >= 15 else "vc+sd-jwt"  # -15 change. Earlier: vc+sd-jwt.

def _container_key(d: int) -> str:
    # -13 renamed credentials_supported -> credential_configurations_supported
    return "credential_configurations_supported" if d >= 13 else "credentials_supported"

def _nonce_supported(d: int) -> bool:
    # Nonce endpoint was introduced in -15
    return d >= 15

def _normalize_display_list(display: List[Dict[str, Any]], draft: int) -> List[Dict[str, Any]]:
    """
    vct_builder emits display like: [{"lang":"en","name":"...","description":"..."}, ...]
    Spec wants: [{"locale":"en","name":"...","description":"..."}, ...]
    """
    out = []
    for d in (display or []):
        print("d = ", d)
        if not isinstance(d, dict):
            continue
        loc = d.get("lang") or d.get("locale") or d.get("language")
        item = {}
        if loc:
            item["locale"] = str(loc)
        if d.get("name"):
            item["name"] = str(d["name"])
        if draft and draft <= 15 and d.get("description"):
            item["description"] = str(d["description"])
        if d.get("rendering"):
            if d["rendering"].get("simple"):
                if d["rendering"]["simple"].get("background_color"):
                    item.update({"background_color": d["rendering"]["simple"]["background_color"]})
                if d["rendering"]["simple"].get("text_color"):
                    item.update({"text_color": d["rendering"]["simple"]["text_color"]})   
                if d["rendering"]["simple"].get("logo"):
                    item["logo"] = {}
                    item["logo"].update({"uri": d["rendering"]["simple"]["logo"].get("uri")})
                    if d["rendering"]["simple"]["logo"].get("alt_text"):
                        item["logo"].update({"alt_text": d["rendering"]["simple"]["logo"]["alt_text"]})
        if item:
            out.append(item)
    return out

def _normalize_path_components(path: List[Any]) -> List[Any]:
    """
    Convert vct_builder '[]' markers to JSON pointer semantics (null for "any array element").
    Keep strings as-is; allow non-negative integers.
    """
    out = []
    for p in (path or []):
        if p == "[]":
            out.append(None)  # becomes JSON null
        elif isinstance(p, int) and p >= 0:
            out.append(p)
        elif isinstance(p, str):
            out.append(p)
    return out

def _claims_for_draft15plus(type_meta: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Build claims description array for draft >=15:
    [{"path":[...], "mandatory":?, "display":[{locale,name,description?}], ...}]
    """
    claims = []
    for c in type_meta.get("claims") or []:
        path = _normalize_path_components(c.get("path") or [])
        if not path:
            continue
        item = {"path": path}
        if c.get("mandatory") is True:
            item["mandatory"] = True
        disp = _normalize_display_list(c.get("display") or [], None)
        if disp:
            item["display"] = disp
        claims.append(item)
    return claims

def _merge_leaf(dst: Dict[str, Any], src: Dict[str, Any]) -> Dict[str, Any]:
    for k, v in (src or {}).items():
        dst[k] = v
    return dst

def _claims_for_legacy(type_meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Drafts <15 used a nested claims object, not path-pointer arrays.
    We synthesize that tree from the same registry paths.
    Each leaf may carry {"mandatory":true?, "display":[...]}.
    Arrays are represented as single-element lists nesting the next level.
    """
    root: Dict[str, Any] = {}

    def set_path(tree: Any, path: List[Any], leaf: Dict[str, Any]):
        if not path:
            if isinstance(tree, dict):
                _merge_leaf(tree, leaf)
            return tree
        head, *rest = path
        if head is None:  # "any array element"
            arr = tree if isinstance(tree, list) else []
            if arr:
                arr[0] = set_path(arr[0], rest, leaf)
            else:
                arr.append(set_path({}, rest, leaf))
            return arr
        else:
            if not isinstance(tree, dict):
                tree = {}
            subtree = tree.get(head)
            tree[head] = set_path(subtree if subtree is not None else {}, rest, leaf)
            return tree

    for c in type_meta.get("claims") or []:
        path = _normalize_path_components(c.get("path") or [])
        if not path:
            continue
        leaf: Dict[str, Any] = {}
        if c.get("mandatory") is True:
            leaf["mandatory"] = True
        disp = _normalize_display_list(c.get("display") or [], None)
        if disp:
            leaf["display"] = disp
        # walk
        first, rest = path[0], path[1:]
        current = root.get(first)
        root[first] = set_path(current if current is not None else {}, rest, leaf)

    return root

def _normalize_type_display(type_meta: Dict[str, Any], draft) -> List[Dict[str, Any]]:
    # vct_builder produces [{"lang", "name", "description?"}, ...]
    return _normalize_display_list(type_meta.get("display") or [], draft)


# ---------- main ----------

def build_credential_issuer_metadata(issuer_id):
    """
    Build /.well-known/openid-credential-issuer from the VC Type registry.
    Includes full claims info for ALL drafts and adds `scope` = "<vct_urn>_scope".
    """
    mode = current_app.config["MODE"]
    issuer = Issuer.query.filter(Issuer.application_api_issuer_id == issuer_id).one_or_none()
    if not issuer:
        return

    d = _draft_int(getattr(issuer, "draft", None))

    # Base metadata
    meta: Dict[str, Any] = {
        "credential_issuer": f"{mode.server}issuer/{issuer_id}",
        "credential_endpoint": f"{mode.server}issuer/{issuer_id}/credential",
        "deferred_credential_endpoint": f"{mode.server}issuer/{issuer_id}/deferred",
        "jwks_uri": f"{mode.server}issuer/{issuer_id}/jwks",
    }
    if _nonce_supported(d):
        meta["nonce_endpoint"] = f"{mode.server}issuer/{issuer_id}/nonce"  # -15+

    # Authorization server reference
    if issuer.authorization_server:
        if d >= 12:
            meta["authorization_servers"] = [issuer.authorization_server]  # -12+
        else:
            meta["authorization_server"] = issuer.authorization_server

    container = _container_key(d)
    meta[container] = {}

    # Load issuer's configured VC Types (array of identifiers)
    try:
        vc_type_list = json.loads(issuer.vc_type or "[]")
    except Exception:
        vc_type_list = []

    for obj in vc_type_list:
        credential_identifier = obj.get("credential_identifier")
        urn = obj.get("urn")
        
        vct_row = VCTRegistry.query.filter(VCTRegistry.vct_urn == urn).first()
        if not vct_row:
            continue

        type_meta = json.loads(vct_row.vct_data) or {}
        config_id = credential_identifier

        cfg: Dict[str, Any] = {
            "format": _fmt_for_draft(d),
            "vct": vct_row.vct,
            "scope": config_id + "_scope",  # as requested
            "cryptographic_binding_methods_supported": [
                "did:jwk",
                "did:key",
                "jwk"
            ],
            "credential_signing_alg_values_supported": [
                "ES256"
            ],
        }

        # Type-level display (credential name/desc), normalized to {locale,...}
        type_display = _normalize_type_display(type_meta, d)
        if type_display:
            cfg["display"] = type_display

        # Claims (properties + display) for all drafts
        if d >= 15:
            claims_arr = _claims_for_draft15plus(type_meta)  # path-pointer array
            if claims_arr:
                cfg["claims"] = claims_arr
        else:
            legacy_claims = _claims_for_legacy(type_meta)    # nested object
            if legacy_claims:
                cfg["claims"] = legacy_claims

        meta[container][config_id] = cfg

    return meta
