"""Built-in WebHawk modules. These ship with the console, not as addon clones."""

from __future__ import annotations

import importlib

MODULES: dict[str, str] = {
    "scope": "Manage in-scope hosts and the shared URL list.",
    "session": "Save a Cookie or Authorization header for later requests.",
    "roost": "Show the engagement: scope, counts, and URL hosts outside scope.",
    "clutch": "List saved requests. Show one with Cookie and Authorization blanked.",
    "blaze": "Label a URL that is already in the shared list.",
    "quill": "Keep a timestamped note pad in the workspace.",
    "snare": "Listen on localhost and keep in-scope traffic. The console stays free. clutch lists the files.",
    "robots": "Turn robots.txt and sitemaps into URLs for pulse.",
    "repeater": "Edit a captured HTTP request, then send it again.",
    "forms": "List form fields and query parameters on a page.",
    "silk": "Spider one site for endpoints, robots.txt, and sitemaps.",
    "vhost": "Request one address once per Host name and compare status, size, and title.",
    "cert": "Read the TLS certificate from one host: subject, names, issuer, and expiry.",
    "redirect": "Follow redirects on one URL and stop if a hop leaves the host or scope.",
    "diff": "Compare two saved responses, or two in-scope URLs.",
    "dns": "Look up A, AAAA, CNAME, MX, TXT, and NS for one in-scope name.",
    "whois": "Look up registrar, dates, and nameservers for one in-scope domain.",
    "jwt": "Decode a token you already have. The signature is not checked.",
    "mail": "Explain MX, SPF, DKIM, and DMARC for one in-scope name.",
    "decode": "Print one page with non-image base64 blocks shown as text.",
}


def load_builtin(name: str):
    if name not in MODULES:
        raise KeyError(name)
    return importlib.import_module(f"hawk.modules.{name}")
