# Changes since 2.7.0

This is everything new in **2.15.0** compared with **2.7.0**, the version on GitHub. It is one list, not a version-by-version history. 2.7.0 already had the scanner, the console, scope, robots, repeater, and the eight reference addons (pulse, ct, carve, phish, ioc, chroma, urlscan, tcurl).

## Console

- The prompt is colored on a terminal: WebHawk in magenta, the selected module in cyan, and `>` in green. It stays plain when `NO_COLOR` is set, `TERM` is empty or `dumb`, or stdout is not a terminal.
- While snare is listening, the prompt shows `[snare:8080]` in yellow. Other modules still run. `snare stop` closes the listener. Leaving the console closes it too. Ctrl-C at the prompt does not.
- `show modules` groups the catalog into Workspace, Enumerate, Review, Watch, and Probe. `show modules Enumerate` (any case) lists that group only. `webhawk modules Enumerate` does the same. A search hit names the group. Tab offers group names after `show modules`, `modules`, and `commands`.
- The startup screen no longer explains Tab. `help` still does.
- Tab adds a space after a unique finished word. A directory match keeps its trailing `/` and does not get a space, so the next Tab can continue the path. Several matches stay unspaced until one remains.
- History still lives in `~/.local/share/webhawk/history`. Lines that contain a cookie, an API key, an Authorization value, or a JWT (`eyJ`) are left out, along with the older token, password, and secret filter.
- There are seven startup banners. Four spell WEBHAWK. Three add a hawk: a perched head, a stoop, and spread wings. A broken stair-step copy of the block letters was replaced. The scanner banner in `webhawk.py` is unchanged.
- `webhawk doctor` also reports whether urllib3 and colorama are installed. Those two, plus requests and aiohttp, stay optional.

## Workspace

The engagement directory is still `./.webhawk`, or `$WEBHAWK_SCOPE` when that is set. Loopback is always in scope. Other hosts need a scope entry. New files:

| File | What it is |
| --- | --- |
| `session.txt` | A Cookie or Authorization value you already have. Writing it does not turn scope on. |
| `requests/` | Raw requests from repeater, forms, and snare. |
| `responses/` | Responses saved by snare, under the same file name as the request. |
| `marks.txt` | Labels from blaze. |
| `notes.txt` | Timestamped lines from quill. |
| `snare/ca.crt` | The CA to trust in the test browser. The key beside it is mode 600. |

`session` is sent by silk, forms, vhost, redirect, diff, and decode. A `--cookie` or `--authorization` flag on one of those commands replaces the saved value for that run. An empty flag omits that header. Repeater sends the request you give it and does not inject the session.

`roost` prints the scope list, the URL count, the saved-request count, and whether a cookie or Authorization value is stored. The values stay hidden. Hosts in `urls.txt` that fall outside scope are listed under `outside`.

`clutch` lists every file in `requests/` with method, host, path, and scope. `clutch show NAME` prints one file and replaces Cookie, Authorization, and Proxy-Authorization with `[blank]`. Nothing is sent. Tab on `clutch show` fills in the file name.

`blaze` hangs a short label on a URL that is already in `urls.txt`. Writing a mark does not create `scope.txt`. An empty mark list deletes `marks.txt`.

`quill` appends a UTC timestamp and a note to `notes.txt`. The stamp is `YYYY-MM-DD HH:MM:SSZ`. Clearing the pad deletes the file. Writing notes does not create `scope.txt`.

## Snare

Snare is a localhost proxy for the test browser. It listens on `127.0.0.1` only (port 8080 unless you pass `--port`). It does not import mitmproxy.

- Each in-scope exchange is saved twice under one name: `requests/example.com-snare-0001.http` and `responses/example.com-snare-0001.http`. The count starts at `0001` for each host. The URL is appended to `urls.txt`. Saving does not create `scope.txt`.
- The live row shows method, status, size, host, path, and that file name. Cookie and Authorization stay in the saved request so repeater can resend it. They are not printed on the row.
- A host inside scope is decrypted. A host outside scope is forwarded and left out of the workspace. With no scope file, only loopback is inside. An off-scope `CONNECT` is an opaque tunnel. An off-scope plain HTTP request is forwarded and not saved.
- HTTPS inside scope needs `openssl` on `PATH`. `snare ca` prints the certificate path and does not listen. Trust that file in the test browser.
- Bodies are forwarded up to 8 MB. The saved copy keeps the first 1 MB (`--max-body`) and the row says `truncated` when the body was longer. Upstream requests ask for `Accept-Encoding: identity`.
- From the WebHawk prompt, `snare` returns immediately and keeps listening. `snare status` prints the port and where files go. A shell `webhawk snare` stays in the foreground until Ctrl-C.
- `diff` accepts the file name alone. Tab on `diff` lists the names in `responses/`. A full path or an in-scope URL still works.
- `--insecure` skips upstream TLS verification.
- HTTP/2, WebSockets, breakpoints, and HAR import are not part of snare. `carve` still reads an old `.mitm` dump when mitmproxy is installed, and it still reads HAR and raw HTTP without it.

## Enumerate

- `forms` lists form fields and link query parameters from a local HTML file, a URL list, or one normal GET of an in-scope page. Names such as `id`, `user`, `search`, `sort`, `order`, and `filter`, plus hidden, password, and disabled fields, are marked `review`. A database error is recorded only when it is already on the page. `--save` writes in-scope raw requests for repeater, with password values blanked. It does not send a modified request.
- `silk` spiders one in-scope URL and stays on that scheme, host, and port. It collects links, form actions, scripts, stylesheets, robots.txt paths, and sitemap locations. Robots paths are listed and not fetched. Off-server links are not followed. Defaults are depth 2 and 40 fetches. Stdout is one URL per line. On a color terminal the spider and the source tags are colored.
- `vhost` connects to one in-scope address and sends one GET per Host name. Names come from the arguments, `--names`, or the scope file. A name outside an active scope file is skipped. Redirects are not followed. The table is status, size, and title.
- `cert` does one TLS handshake and prints subject, names, issuer, and dates. The certificate is parsed in Python. There is no cryptography package.
- `redirect` prints each hop and stops before a hop that leaves the original hostname or scope. The cap is a short chain. Scheme and port may change on the same hostname.
- `dns` sends one query each for A, AAAA, CNAME, MX, TXT, and NS. It does not chase a CNAME, guess names, or fall back to a public resolver. `--resolver` must be an IP address. An unresolved CNAME is marked for review.
- `whois` reads registrar, creation, expiry, and nameservers for one in-scope domain. Scope is checked before any socket. `--server` must be an IP and is the only server queried. Without it, whois.iana.org is asked for one referral and that registry is queried once. A bare IP is refused. Expiry in the past or within 30 days is marked for review.
- `mail` explains MX, SPF, DMARC (`_dmarc`), and DKIM for selectors you pass with `--selector`. It does not guess selectors and does not resolve MX hosts. A long DKIM key is reported as present and is not printed. `--resolver` must be an IP address.

## Review

- `diff` compares two saved responses, or two in-scope URLs with one GET each. A path that exists is read from disk. A bare file name is read from `responses/`. The report skips the Date header. Compared bodies are capped.
- `jwt` decodes a token you already have and prints the header and claims. It does not check the signature and it does not forge a token. `--session` reads the saved Authorization value and strips a leading Bearer. `alg` none, a past `exp`, a future `nbf`, and a missing `exp` are review notes.
- `decode` prints one in-scope page, or a local file, with non-image base64 written out as text. Image data URIs and PNG, JPEG, GIF, WEBP, ICO, and BMP bytes stay encoded. Unmarked blocks shorter than 64 characters stay encoded. `--min` changes that floor. Data URIs are considered at any length. Redirects stop before a hop that leaves the host or scope. The body cap is 1 MB.
- `repeater` is unchanged in role: edit one raw request, then send that copy. Snare and forms now fill `requests/` with files it can open.

## Probe and the addons

- `skiff` ships in `addons/skiff/`. It is the HTTP fuzzer: replace `FUZZ` from a wordlist. `webhawk skiff --help` is local. `--dry-run` prints the requests and does not connect. It needs `requests`, `urllib3`, and `colorama`. Scope is not enforced inside the clone.
- `requirements.txt` now includes `requests`, `urllib3`, `aiohttp`, and `colorama` alongside rich, httpx, and playwright. `ct` needs aiohttp. phish and ioc need requests.
- Addon lookup is unchanged: `$WEBHAWK_ADDONS`, then `./addons`, then `../addons`.

## Banners on the newer modules

silk, whois, jwt, mail, decode, roost, clutch, blaze, quill, and snare each print a small ASCII banner on a color terminal. `--plain` skips the banner and the row colors. The banner goes to stderr. A pipe stays plain.
