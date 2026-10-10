"""HTTP client shared by the enumeration modules.

trust_env is off so the host that was allowed is the host that is contacted.
Redirects are not followed here. The redirect module records each hop itself.
"""

from __future__ import annotations

import httpx

from hawk import VERSION
from hawk.session import apply_headers


def client(
    timeout: float,
    *,
    insecure: bool = False,
    cookie: str | None = None,
    authorization: str | None = None,
    headers: dict[str, str] | None = None,
) -> httpx.Client:
    base = {
        "User-Agent": f"WebHawk/{VERSION}",
        "Accept-Encoding": "identity",
    }
    if headers:
        base.update(headers)
    base = apply_headers(base, cookie=cookie, authorization=authorization)
    return httpx.Client(
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
        verify=not insecure,
        headers=base,
    )


def read_body(response: httpx.Response, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        if total >= limit:
            break
        piece = chunk[: limit - total]
        chunks.append(piece)
        total += len(piece)
    return b"".join(chunks)
