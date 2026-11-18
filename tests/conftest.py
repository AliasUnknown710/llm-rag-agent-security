from collections.abc import Generator
import shutil
import pytest
from src.config import AUDIT_LOG_PATH, SANDBOX_DIR
from src.security.audit_logger import close_audit_logger


@pytest.fixture(autouse=True)
def clean_test_artifacts() -> Generator[None, None, None]:
    yield
    close_audit_logger()
    for log_file in AUDIT_LOG_PATH.parent.glob(f"{AUDIT_LOG_PATH.name}*"):
        if log_file.is_file():
            log_file.unlink()
    if SANDBOX_DIR.exists():
        shutil.rmtree(SANDBOX_DIR)
    secret_file = SANDBOX_DIR.parent / "secret_keys.env"
    if secret_file.exists():
        secret_file.unlink()