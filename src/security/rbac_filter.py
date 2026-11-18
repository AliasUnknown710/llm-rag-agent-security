from src.exceptions import AccessControlViolationError

ROLE_PERMISSIONS: dict[str, list[str]] = {
    "guest": ["public"],
    "employee": ["public", "employee"],
    "executive": ["public", "employee", "executive"],
}


def build_chroma_rbac_filter(user_role: str) -> dict[str, dict[str, list[str]]]:
    allowed_tiers = ROLE_PERMISSIONS.get(user_role)
    if not allowed_tiers:
        raise AccessControlViolationError(f"Unauthorized or unrecognized role '{user_role}'.")
    return {"access_tier": {"$in": allowed_tiers}}