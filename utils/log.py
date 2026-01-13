import json
import os
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
import logging
from typing import Optional, Dict, Any

_LOGGERS: Dict[str, logging.Logger] = {}
_LOCK = threading.Lock()

def _safe_filename(s: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in s)

def get_wallet_logger(wallet_id: str, base_dir: str = "logs/wallets") -> logging.Logger:
    wallet_id_safe = _safe_filename(wallet_id)

    with _LOCK:
        existing = _LOGGERS.get(wallet_id_safe)
        if existing is not None:
            return existing

        os.makedirs(base_dir, exist_ok=True)
        path = os.path.join(base_dir, f"{wallet_id_safe}.jsonl")

        logger_name = f"wallet_event.{wallet_id_safe}"
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.INFO)
        logger.propagate = False  # avoid double logging via root

        # Guard against duplicate handlers (common with reloads)
        for h in list(logger.handlers):
            if isinstance(h, RotatingFileHandler) and getattr(h, "baseFilename", None) == os.path.abspath(path):
                _LOGGERS[wallet_id_safe] = logger
                return logger

        handler = RotatingFileHandler(
            path,
            maxBytes=5 * 1024 * 1024,  # 5MB
            backupCount=10,            # keep last 10
            encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

        _LOGGERS[wallet_id_safe] = logger
        return logger

def log_wallet_event(
    wallet_id: str,
    event_type: str,
    details: Optional[Dict[str, Any]] = None,
    actor: Optional[str] = None,
    subject: Optional[str] = None,
    trace_id: Optional[str] = None,
    task_id: Optional[str] = None,
    base_dir: str = "logs/wallets",
) -> None:
    evt: Dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "wallet_id": wallet_id,
        "event_type": event_type,
        "actor": actor,
        "subject": subject,
        "trace_id": trace_id,
        "task_id": task_id,
        "details": details or {},
    }

    logger = get_wallet_logger(wallet_id, base_dir=base_dir)
    logger.info(json.dumps(evt, ensure_ascii=False))
