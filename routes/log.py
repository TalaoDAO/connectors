# auditlog.py
import os, json, uuid, re, datetime, logging
from functools import lru_cache
from flask import current_app, request, g, Response, stream_with_context
from utils import oidc4vc
from db_model import Verifier, Signin

logging.basicConfig(level=logging.INFO)

REDACT_HEADERS = {"authorization", "cookie", "set-cookie"}
REDACT_KEYS = re.compile(r"(secret|token|password|pass|authorization|cookie|api[-_]?key)", re.I)


# ---------- time & json helpers

def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)

def iso(ts=None):
    return (ts or _utcnow()).isoformat()

def safe_json(obj):
    """Redact obvious secrets in JSON-ish dicts recursively."""
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if REDACT_KEYS.search(k) else safe_json(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [safe_json(v) for v in obj]
    return obj


# ---------- body capture helpers

def capture_body(limit=50_000, per_value_limit=4096):
    """
    Safely capture a readable preview of the request body without breaking downstream reading.
    Handles JSON, x-www-form-urlencoded and multipart/form-data.
    """
    ctype = (request.mimetype or "").lower()
    clen = request.content_length or 0

    def _truncate_text(s: str, max_bytes: int) -> str:
        b = s.encode("utf-8", errors="replace")
        if len(b) <= max_bytes:
            return s
        s_cut = b[:max_bytes].decode("utf-8", errors="replace")
        return s_cut + "…[truncated]"

    # 1) application/x-www-form-urlencoded
    if ctype == "application/x-www-form-urlencoded":
        pairs = []
        total_bytes = 0
        for key, values in request.form.lists():
            for v in values:
                v_disp = _truncate_text(v, per_value_limit)
                pairs.append(f"{key}={v_disp}")
                total_bytes += len(key.encode("utf-8")) + 1 + len(v.encode("utf-8"))
                if sum(len(p) + 1 for p in pairs) > limit:
                    pairs.append("…[truncated]")
                    break
            else:
                continue
            break
        preview = "&".join(pairs) if pairs else "∅ (no fields)"
        return preview, (clen or total_bytes)

    # 2) multipart/form-data
    if ctype == "multipart/form-data":
        lines = []
        if request.form:
            lines.append("Fields:")
            for key, values in request.form.lists():
                for v in values:
                    lines.append(f"  {key}={_truncate_text(v, per_value_limit)}")
        if request.files:
            lines.append("Files:")
            for name, fs in request.files.items(multi=True):
                size = getattr(fs, "content_length", None)
                meta = f"filename={fs.filename!r} content_type={fs.content_type}"
                if size is not None:
                    meta += f" size={size}"
                lines.append(f"  {name}: {meta}")
        if not lines:
            lines = ["∅ (no fields/files)"]
        text = "\n".join(lines)
        if len(text.encode("utf-8", "replace")) > limit:
            text = _truncate_text(text, limit)
        return text, (clen or 0)

    # 3) JSON (pretty)
    if "json" in ctype:
        try:
            obj = request.get_json(silent=True)
        except Exception:
            obj = None
        if obj is not None:
            try:
                pretty = json.dumps(obj, ensure_ascii=False, indent=2)
            except Exception:
                pretty = str(obj)
            if len(pretty.encode("utf-8", "replace")) > limit:
                pretty = _truncate_text(pretty, limit)
            return pretty, (clen or len((request.get_data(cache=True) or b"")))
        # fallthrough to raw

    # 4) raw
    try:
        data = request.get_data(cache=True) or b""
    except Exception:
        return None, 0
    b = data[:limit]
    truncated = len(data) > limit
    try:
        text = b.decode(request.charset or "utf-8", errors="replace")
    except Exception:
        text = b.decode("utf-8", errors="replace")
    return (text + ("…[truncated]" if truncated else "")), len(data)


def response_body(response, limit=100_000):
    """Extract response body text without breaking streaming."""
    try:
        passthrough = getattr(response, "direct_passthrough", False)
        response.direct_passthrough = False
        data = response.get_data() or b""
        response.direct_passthrough = passthrough
    except Exception:
        return None, 0
    b = data[:limit]
    truncated = len(data) > limit
    try:
        text = b.decode(response.charset or "utf-8", errors="replace")
    except Exception:
        text = b.decode("utf-8", errors="replace")
    return (text + ("…[truncated]" if truncated else "")), len(data)


def redact_headers(headers):
    out = {}
    # headers may be EnvironHeaders; convert to dict safely
    for k, v in dict(headers).items():
        if k.lower() in REDACT_HEADERS:
            out[k] = "[REDACTED]"
        else:
            out[k] = v
    return out


# ---------- log storage

@lru_cache(maxsize=1)
def base_log_dir():
    # configurable root dir
    return current_app.config.get(
        "AUDIT_LOG_DIR", os.path.join(current_app.instance_path, "./log")
    )

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def open_logfile(id, type_):
    date = datetime.date.today().isoformat()
    if type_ == "verifier":
        dir_ = os.path.join(base_log_dir(), "verifier", id, date)
    else:
        dir_ = os.path.join(base_log_dir(), "signin", id, date)
    ensure_dir(dir_)
    file_path = os.path.join(dir_, f"{id}.log")
    return open(file_path, "a", encoding="utf-8")


def write_entry(fp, entry):
    """Human-friendly header + machine-friendly JSON."""
    hdr = f"[{entry['ts']}] {entry['phase']} — {entry['method']} {entry['path']} • {entry.get('status','')}".strip()
    fp.write(hdr + "\n")
    fp.write(json.dumps(entry, ensure_ascii=False) + "\n\n")
    fp.flush()


# ---------- SSE endpoints

def verifier_test_stream():
    red = current_app.config["REDIS"]

    @stream_with_context
    def test_stream():
        pubsub = red.pubsub()
        pubsub.subscribe("test_verifier")
        for message in pubsub.listen():
            if message.get("type") == "message":
                yield "data: %s\n\n" % message["data"].decode()

    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    }
    return Response(test_stream(), headers=headers)


def signin_test_stream():
    red = current_app.config["REDIS"]

    @stream_with_context
    def test_stream():
        pubsub = red.pubsub()
        pubsub.subscribe("test_signin")
        for message in pubsub.listen():
            if message.get("type") == "message":
                yield "data: %s\n\n" % message["data"].decode()

    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    }
    return Response(test_stream(), headers=headers)


def issuer_inspect_stream():
    red = current_app.config["REDIS"]
    @stream_with_context
    def test_stream():
        pubsub = red.pubsub()
        pubsub.subscribe("issuer_inspect")
        for message in pubsub.listen():
            if message.get("type") == "message":
                yield "data: %s\n\n" % message["data"].decode()
    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    }
    return Response(test_stream(), headers=headers)


def publish(red, session_id, entry, type_):
    """Route events to the right test channel."""
    event_data = json.dumps({"session_id": session_id, "data": entry})
    if type_ == "verifier":
        red.publish("test_verifier", event_data)
    else:
        red.publish("test_signin", event_data)


# ---------- gating

def _verifier_should_log():
    verifier_id = g._audit.get("verifier_id")
    if not verifier_id:
        return False
    verifier = Verifier.query.get(verifier_id)
    if not verifier:
        logging.info("Verifier %s not found; skip log", verifier_id)
        return False
    if not verifier.log and not verifier.test:
        logging.info("Verifier %s logging disabled", verifier_id)
        return False
    return True

def _signin_should_log():
    signin_id = g._audit.get("signin_id")
    if not signin_id:
        return False
    signin = Signin.query.get(signin_id)
    if not signin:
        logging.info("Signin %s not found; skip log", signin_id)
        return False
    if not signin.log and not signin.test:
        logging.info("Signin %s logging disabled", signin_id)
        return False
    return True


# ---------- init & hooks

def init_audit_logging(app):
    """
    Call from app factory: init_audit_logging(app)
    """
    # SSE (test) endpoints
    app.add_url_rule("/verifier/wallet/test/stream", view_func=verifier_test_stream, methods=["GET"])
    app.add_url_rule("/signin/wallet/test/stream", view_func=signin_test_stream, methods=["GET"])
    app.add_url_rule("/issuer/wallet/inspect/stream", view_func=issuer_inspect_stream, methods=["GET"])

    # -------- context builder: set g._audit for signin/verifier request/callback
    @app.before_request
    def _audit_identify():
        g._audit = {}  # local bag
        path = (request.path or "")
        red = current_app.config["REDIS"]

        if path.startswith("/signin/wallet/request_uri/") or path.startswith("/verifier/wallet/request_uri/"):
            stream_id = path.rsplit("/", 1)[-1]
            try:
                raw = red.get(stream_id)
                if not raw:
                    logging.error("Audit: no JWT stored for stream_id=%s", stream_id)
                    return
                token = raw.decode()
                # tolerate accidental quoted JSON storage
                if token.startswith('"') and token.endswith('"'):
                    token = json.loads(token)
            except Exception:
                logging.exception("Audit: error reading JWT for stream_id=%s", stream_id)
                return

            try:
                nonce = oidc4vc.get_payload_from_token(token)["nonce"]
            except Exception:
                logging.exception("Audit: cannot parse nonce from request_uri token")
                return

        # Handle: /signin/wallet/callback  (Direct Post or Direct Post JWT)
        elif path.startswith("/signin/wallet/callback") or  path.startswith("/verifier/wallet/callback"):
            if request.form.get("response"):
                try:
                    response = oidc4vc.get_payload_from_token(request.form["response"])
                    logging.info("Audit: direct_post.jwt")
                except Exception:
                    logging.exception("Audit: invalid direct_post.jwt")
                    return
            else:
                logging.info("Audit: direct_post (form)")
                response = request.form

            vp_token = response.get("vp_token")
            if not vp_token:
                return  # nothing to audit
            try:
                nonce = oidc4vc.get_payload_from_token(vp_token.split("~")[-1])["nonce"]
            except Exception:
                logging.exception("Audit: cannot parse nonce from vp_token")
                return

        else:
            # not part of the signin (or verifier) audited flow; skip
            return

        # Look up session & flags by nonce
        try:
            blob = red.get(nonce)
            if not blob:
                logging.error("Audit: no nonce payload for %s", nonce)
                return
            data = json.loads(blob.decode())
        except Exception:
            logging.exception("Audit: error reading nonce %s", nonce)
            return

        # Fill audit context
        g._audit["nonce"] = nonce
        g._audit["session_id"] = data.get("session_id")

        if path.startswith("/signin/"):
            signin_id = data.get("signin_id")
            if signin_id is None:
                logging.error("Audit: missing signin_id for nonce %s", nonce)
                return
            g._audit["signin_id"] = str(signin_id)
            signin = Signin.query.get(signin_id)
            g._audit["test"] = bool(getattr(signin, "test", False))
            g._audit["log"] = bool(getattr(signin, "log", False))
            g._audit["type"] = "signin"
        elif path.startswith("/verifier/"):
            verifier_id = data.get("verifier_id")
            if verifier_id is None:
                logging.error("Audit: missing verifier_id for nonce %s", nonce)
                return
            g._audit["verifier_id"] = str(verifier_id)
            verifier = Verifier.query.get(verifier_id)
            g._audit["test"] = bool(getattr(verifier, "test", False))
            g._audit["log"] = bool(getattr(verifier, "log", False))
            g._audit["type"] = "verifier"

        logging.info("Audit identify OK: %s", g._audit)

    # -------- before_request: publish "request"
    @app.before_request
    def _audit_before():
        if not hasattr(g, "_audit") or g._audit.get("type") not in {"signin", "verifier"}:
            return

        # Respect toggles
        type_ = g._audit["type"]
        if type_ == "signin" and not (_signin_should_log() or g._audit.get("test")):
            return
        if type_ == "verifier" and not (_verifier_should_log() or g._audit.get("test")):
            return

        red = current_app.config["REDIS"]
        g._audit["start"] = _utcnow()
        g._audit["request_id"] = uuid.uuid4().hex

        body_text, body_bytes = capture_body()
        entry = {
            "ts": iso(g._audit["start"]),
            "phase": "request",
            "nonce": g._audit["nonce"],
            "method": request.method,
            "content_type": request.content_type,
            "path": request.path,
            "query": request.args.to_dict(flat=False),
            "headers": redact_headers(request.headers),
            "body_preview": body_text,
            "body_bytes": body_bytes,
            "remote_addr": request.remote_addr,
            "endpoint": request.endpoint,
        }

        # Publish to SSE if test
        if g._audit.get("test"):
            publish(red, g._audit["session_id"], entry, type_)

        # Append to file if log
        if g._audit.get("log"):
            if type_ == "verifier":
                with open_logfile(g._audit["verifier_id"], "verifier") as fp:
                    write_entry(fp, entry)
            else:
                with open_logfile(g._audit["signin_id"], "signin") as fp:
                    write_entry(fp, entry)

    # -------- after_request: publish "response"
    @app.after_request
    def _audit_after(response):
        if not hasattr(g, "_audit") or g._audit.get("type") not in {"signin", "verifier"}:
            return response

        type_ = g._audit["type"]
        if type_ == "signin" and not (_signin_should_log() or g._audit.get("test")):
            return response
        if type_ == "verifier" and not (_verifier_should_log() or g._audit.get("test")):
            return response

        red = current_app.config["REDIS"]
        stop = _utcnow()
        body_text, body_bytes = response_body(response)
        entry = {
            "ts": iso(stop),
            "phase": "response",
            "nonce": g._audit.get("nonce"),
            "method": request.method,
            "content_type": response.headers.get("Content-Type"),
            "path": request.path,
            "status": int(getattr(response, "status_code", 0)),
            "headers": redact_headers(getattr(response, "headers", {})),
            "body_preview": body_text,
            "body_bytes": body_bytes,
            "duration_ms": int((stop - g._audit.get("start", stop)).total_seconds() * 1000),
        }

        if g._audit.get("test"):
            publish(red, g._audit["session_id"], entry, type_)
        if g._audit.get("log"):
            if type_ == "verifier":
                with open_logfile(g._audit["verifier_id"], "verifier") as fp:
                    write_entry(fp, entry)
            else:
                with open_logfile(g._audit["signin_id"], "signin") as fp:
                    write_entry(fp, entry)
        return response

    # -------- teardown_request: publish "error" if exception
    @app.teardown_request
    def _audit_teardown(exc):
        if exc is None or not hasattr(g, "_audit") or g._audit.get("type") not in {"signin", "verifier"}:
            return

        type_ = g._audit["type"]
        if type_ == "signin" and not (_signin_should_log() or g._audit.get("test")):
            return
        if type_ == "verifier" and not (_verifier_should_log() or g._audit.get("test")):
            return

        red = current_app.config["REDIS"]
        stop = _utcnow()
        entry = {
            "ts": iso(stop),
            "phase": "error",
            "nonce": g._audit.get("nonce"),
            "method": request.method,
            "path": request.path,
            "status": 500,
            "error": repr(exc),
        }
        if g._audit.get("test"):
            publish(red, g._audit["session_id"], entry, type_)
        if g._audit.get("log"):
            if type_ == "verifier":
                with open_logfile(g._audit["verifier_id"], "verifier") as fp:
                    write_entry(fp, entry)
            else:
                with open_logfile(g._audit["signin_id"], "signin") as fp:
                    write_entry(fp, entry)
