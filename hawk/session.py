"""Saved Cookie and Authorization headers.

The file is session.txt in the scope workspace. It does not turn scope on.
silk, forms, vhost, redirect, and diff send these headers on their requests.
A flag on one command replaces the saved value for that run.
"""

from __future__ import annotations

from hawk.workspace import workspace_dir

_KEYS = ("cookie", "authorization")


def session_path():
    return workspace_dir() / "session.txt"


def load_session() -> dict[str, str]:
    path = session_path()
    if not path.is_file():
        return {}
    found: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        if key in _KEYS and value.strip():
            found[key] = value.strip()
    return found


def write_session(values: dict[str, str]) -> None:
    kept = {key: values[key].strip() for key in _KEYS if values.get(key, "").strip()}
    path = session_path()
    if not kept:
        if path.exists():
            path.unlink()
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# WebHawk session. cookie and authorization only.", ""]
    for key in _KEYS:
        if key in kept:
            lines.append(f"{key}: {kept[key]}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def apply_headers(
    headers: dict[str, str],
    *,
    cookie: str | None,
    authorization: str | None,
) -> dict[str, str]:
    """Fill Cookie and Authorization. None uses the saved value. '' sends neither."""
    saved = load_session()
    merged = dict(headers)
    cookie_value = saved.get("cookie", "") if cookie is None else cookie.strip()
    auth_value = saved.get("authorization", "") if authorization is None else authorization.strip()
    if cookie_value:
        merged["Cookie"] = cookie_value
    else:
        merged.pop("Cookie", None)
    if auth_value:
        merged["Authorization"] = auth_value
    else:
        merged.pop("Authorization", None)
    return merged
