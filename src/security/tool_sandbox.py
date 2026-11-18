from pathlib import Path
from pydantic import BaseModel, Field, field_validator
from src.config import SANDBOX_DIR
from src.exceptions import ToolSandboxViolationError

APPROVED_FILES: set[str] = {"welcome.txt", "holiday_schedule.txt"}


class SandboxedFileInput(BaseModel):
    filename: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Approved public filename inside sandbox_docs",
    )

    @field_validator("filename")
    @classmethod
    def validate_allowlisted_filename(cls, value: str) -> str:
        if any(token in value for token in ("/", "\\", "..", "~", "$")):
            raise ToolSandboxViolationError(f"Path traversal or shell metacharacter rejected ('{value}').")
        if value not in APPROVED_FILES:
            raise ToolSandboxViolationError(f"File '{value}' is not in the approved read allowlist.")
        return value


def resolve_safe_path(filename: str) -> Path:
    """Resolves canonical path and enforces strict confinement inside SANDBOX_DIR."""
    base_dir = SANDBOX_DIR.resolve()
    target_path = (base_dir / filename).resolve()
    if target_path.parent != base_dir:
        raise ToolSandboxViolationError(f"Canonical path escape blocked ('{target_path}').")
    return target_path