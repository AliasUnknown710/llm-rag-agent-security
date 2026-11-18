from datetime import datetime, timezone
import json
import logging
from logging.handlers import RotatingFileHandler
from src.config import AUDIT_LOG_PATH

_LOGGER_NAME = "finsec.security.audit"


def _get_audit_logger() -> logging.Logger:
    logger = logging.getLogger(_LOGGER_NAME)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        logger.propagate = False
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            filename=str(AUDIT_LOG_PATH),
            maxBytes=5 * 1024 * 1024,  # 5 MB rotation threshold
            backupCount=3,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    return logger


def close_audit_logger() -> None:
    """Flushes and closes file handles cleanly (required on Windows before log rotation/cleanup)."""
    logger = logging.getLogger(_LOGGER_NAME)
    for handler in list(logger.handlers):
        handler.flush()
        handler.close()
        logger.removeHandler(handler)


def log_security_event(
    event_type: str,
    component: str,
    actor_role: str,
    status: str,
    details: str,
    owasp_id: str = "N/A",
) -> None:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "owasp_id": owasp_id,
        "event_type": event_type,
        "component": component,
        "actor_role": actor_role,
        "status": status,
        "details": details,
    }
    _get_audit_logger().info(json.dumps(record))
