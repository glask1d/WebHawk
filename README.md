<p align="center">
  <img src="https://github.com/user-attachments/assets/d4e3b632-521f-4030-9a91-86a6192f7404" alt="WebHawk — HTTP / HTTPS attack-surface mapper" width="100%">
</p>

# WebHawk

**Version 2.15.0** — an authorized HTTP toolkit. It maps hosts, keeps an engagement workspace, and runs the recon modules from one console.

Use it on lab boxes, your own servers, and scoped engagements. What changed since the published 2.7.0 release is in [CHANGELOG.md](CHANGELOG.md).

Only run it against systems you own or have written permission to test.

**Start here:** [Install](#install) · [Three ways to run it](#three-ways-to-run-it) · [Modules](#modules) · [Files on disk](#files-on-disk) · [Snare](#log-the-browser-with-snare) · [Console](#console) · [Scanner](#scanner)

## Install

Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium        # only for scan --screenshots
pip install -e .                   # optional: puts webhawk on PATH
webhawk doctor
```

`pip install -r requirements.txt` is the full set: rich, httpx, playwright, requests, urllib3, aiohttp, and colorama. `pip install -e .` alone installs rich and httpx and adds the `webhawk` command. Without that install, `python webhawk.py` from this directory does the same job.

`webhawk doctor` reports Python, the packages, and whether `curl`, `torsocks`, and `tor` are present for tcurl. requests, urllib3, aiohttp, colorama, playwright, and mitmproxy are optional. The module that needs one will say so when it is missing.

## Three ways to run it

A host or a scan flag still scans. A module name runs that module once. No arguments, in a terminal, opens the console.

```bash
webhawk 127.0.0.1 --ports 80,443
webhawk silk http://127.0.0.1:8080/
webhawk
```

Inside the console the same module is `use`, then `run`:

```text
WebHawk > use silk
WebHawk silk > run http://127.0.0.1:8080/
```

`webhawk help` is the command guide. `webhawk help scan` prints every scan flag. `webhawk <module> --help` prints that module's flags. `webhawk examples` prints copy-paste lines.

A host whose name matches a command needs an explicit scan: `webhawk scan modules` or `webhawk -- pulse`. A positional argument that is an existing file is not scanned as a hostname. Put host lists on `-l`.

## Modules

`webhawk modules` lists every module by group. `webhawk modules Enumerate` lists one group. Names stay flat: `use silk`, `webhawk silk`.

### Workspace

These keep the engagement. They share `./.webhawk` (or `$WEBHAWK_SCOPE`).

| Module | What it does | Example |
| --- | --- | --- |
| `scope` | Allow-list and the shared URL list | `webhawk scope add app.internal` |
| `session` | Store a Cookie or Authorization you already have | `webhawk session show` |
| `roost` | Counts, scope entries, and hosts outside scope | `webhawk roost` |
| `clutch` | List saved requests, or print one with secrets blanked | `webhawk clutch` |
| `blaze` | Label a URL that is already in the list | `webhawk blaze add login https://app.internal/login` |
| `quill` | Timestamped notes | `webhawk quill add checked the login form` |
| `snare` | Localhost proxy. Stays up beside the console | `snare` |

### Enumerate

| Module | What it does | Example |
| --- | --- | --- |
| `scan` | Map HTTP and HTTPS on a host | `webhawk 127.0.0.1` |
| `silk` | Spider one site, including robots and sitemaps | `webhawk silk http://127.0.0.1:8080/` |
| `robots` | Turn a robots.txt or sitemap into URLs | `webhawk robots robots.txt --base https://app.internal` |
| `forms` | List form fields and query parameters | `webhawk forms page.html --base https://app.internal` |
| `vhost` | One address, once per Host name | `webhawk vhost http://127.0.0.1:8080/ app.internal` |
| `cert` | Read the TLS certificate | `webhawk cert https://app.internal` |
| `dns` | A, AAAA, CNAME, MX, TXT, and NS | `webhawk dns app.internal` |
| `whois` | Registrar, dates, and nameservers | `webhawk whois app.internal` |
| `mail` | MX, SPF, DMARC, and named DKIM selectors | `webhawk mail app.internal --selector s1` |
| `redirect` | Follow a redirect chain and stop at the scope edge | `webhawk redirect http://127.0.0.1:8080/start` |
| `pulse` | Check which URLs are live | `webhawk pulse .webhawk/urls.txt` |
| `ct` | Certificate-transparency names (crt-scout) | `webhawk ct app.internal -c` |

### Review

| Module | What it does | Example |
| --- | --- | --- |
| `repeater` | Edit a saved request and send that copy | `webhawk repeater captured.http --print` |
| `diff` | Compare two saved responses, or two in-scope URLs | `webhawk diff before.http after.http` |
| `jwt` | Decode a token you already have | `webhawk jwt --session` |
| `decode` | Print a page with non-image base64 shown as text | `webhawk decode http://127.0.0.1:8080/` |
| `carve` | Pull links out of a HAR, raw HTTP, or a .mitm dump | `webhawk carve capture.har --unique` |
| `tcurl` | Fetch through Tor | `webhawk tcurl example.com -I` |

### Watch

| Module | What it does | Example |
| --- | --- | --- |
| `phish` | Phishunt feed, campaigns, and a passive URL score | `webhawk phish --help` |
| `ioc` | TweetFeed indicators (IOCaw) | `webhawk ioc --help` |
| `chroma` | abuse.ch (chromahaus) | `webhawk chroma --help` |
| `urlscan` | urlscan.io lookup | `webhawk urlscan --help` |

`phish deep` and `chroma download` stay hidden until you set `COMMAND` to that subcommand.

### Probe

| Module | What it does | Example |
| --- | --- | --- |
| `skiff` | Replace `FUZZ` from a wordlist | `webhawk skiff -u http://127.0.0.1/FUZZ -w words.txt --dry-run` |

## Files on disk

Scope, URLs, and saved traffic live in `./.webhawk`. Set `WEBHAWK_SCOPE` to put that directory somewhere else.

| Path | What it holds |
| --- | --- |
| `scope.txt` | Hosts, domains, `*.domains`, and CIDRs. Created by `scope init`. |
| `urls.txt` | The shared URL list. |
| `session.txt` | Cookie and Authorization. Hidden by roost. Blanked by clutch show. |
| `requests/` | Raw requests. clutch lists these. repeater sends one. |
| `responses/` | Responses from snare. diff reads these. |
| `marks.txt` | blaze labels. |
| `notes.txt` | quill notes. |
| `snare/ca.crt` | CA certificate for the test browser. |

Loopback is always allowed. Any other host needs a scope entry. A domain includes its subdomains. `*.example.com` is subdomains only. An address matches that address or a CIDR.

```bash
webhawk scope init
webhawk scope add app.internal '*.lab.internal' 10.1.0.0/16
webhawk scope import-urls found.txt
webhawk scope urls
```

`import-urls` keeps lines that contain `://` and whose host is in scope. `scope urls` prints the list. Point pulse at it with `webhawk pulse .webhawk/urls.txt`.

## Log the browser with snare

Snare replaces the daily "point the browser at a local proxy and keep the traffic" workflow. From the console it stays up, and the prompt comes back:

```text
WebHawk > snare
WebHawk [snare:8080] >
```

Point the test browser at `127.0.0.1:8080`. Trust the certificate from `snare ca` so HTTPS inside scope can be read. That needs `openssl` on `PATH`.

```bash
webhawk snare ca
```

Each in-scope exchange is saved twice under one name:

```text
.webhawk/requests/example.com-snare-0001.http
.webhawk/responses/example.com-snare-0001.http
```

The count starts over for each host, so a long list sorts by site. The live row ends with the file name. Tab on `clutch show` and `diff` fills that name in, so you do not type the directory:

```text
WebHawk > clutch
WebHawk > clutch show example.com-snare-0001.http
WebHawk > diff example.com-snare-0001.http example.com-snare-0002.http
WebHawk > snare status
WebHawk > snare stop
```

`clutch show` prints the request and replaces Cookie and Authorization with `[blank]`. The saved file still has them, so repeater can resend it. `diff` compares the two responses. A full path still works when the file is somewhere else.

A host outside scope is forwarded and not written. With no scope file, only loopback is kept. A shell `webhawk snare` holds that terminal until Ctrl-C. Open the console when you want the proxy and the other modules together.

A saved body over 1 MB is marked `truncated`. The browser still gets the full body, up to 8 MB.

## Console

`webhawk` in a terminal prints one of seven banners and a short command list. Four spell WEBHAWK. Three add a hawk. `banner` picks a different one. `help` prints the longer guide.

```text
WebHawk > use pulse
WebHawk pulse > show options
WebHawk pulse > set FILE urls.txt
WebHawk pulse > set FOLLOW_REDIRECTS true
WebHawk pulse > run
WebHawk pulse > back
WebHawk > exit
```

On a color terminal, WebHawk is magenta, the module name is cyan, and `>` is green. While snare is listening, `[snare:8080]` is yellow.

Option names are the argument destination in uppercase. Pulse's URL file is `FILE`. `set FILE=urls.txt` is the same as `set FILE urls.txt`. `true`, `yes`, `on`, and `1` turn a switch on. `unset FILE` forgets one value. `unset all` clears the module you have selected.

Saved values stay on that module across `back`. They fill whatever you leave off the next `run`. Arguments you type on `run` win. Typing the module name runs it once: `pulse urls.txt`. `run --help` prints that module's flags. Ctrl-C stops the module and returns to the prompt. `exit` leaves. If snare is up, `exit` stops it.

Tab completes commands, modules, options, choices, group names, and paths, then leaves a space. A directory keeps its trailing slash so the path can continue. `diff` and `clutch show` offer the saved file names, so you do not type the directory. Up and down recall history. History is `~/.local/share/webhawk/history` (`WEBHAWK_HISTORY` overrides it). A line that contains a token, password, secret, cookie, API key, or JWT is left out.

`search spider` lists modules whose name or description matches, and it names the group.

`tcurl` needs `curl`, `torsocks`, and a Tor daemon on `127.0.0.1:9050`. Curl flags that take a value go in `EXTRA`:

```text
WebHawk tcurl > set URL example.com
WebHawk tcurl > set EXTRA -A 'WebHawk' -H 'Accept: application/json'
WebHawk tcurl > run -I
```

Shell completion, for the command name and scan flags:

```bash
webhawk completion bash > ~/.local/share/bash-completion/completions/webhawk
webhawk completion zsh > ~/.zsh/completions/_webhawk
```

## Module notes

The newer modules print a small banner on a color terminal. `--plain` skips it. Pipes stay plain.

**scope.** `scope init` creates the directory and does not wipe an existing scope file.

**session.** `session set` writes `session.txt` and leaves scope off. silk, forms, vhost, redirect, diff, and decode send the saved Cookie and Authorization. A flag on one run replaces the saved value. An empty flag omits that header. Repeater does not add them.

**robots.** Relative paths need `--base`. With a scope file, in-scope URLs are appended to `urls.txt` unless you pass `--no-workspace`. `--fetch` requests one in-scope URL and follows a sitemap it names. A redirect onto a host outside scope is discarded. URLs go to stdout. The summary goes to stderr.

**repeater.** `--print` writes the edited request and does not connect. The host that would be contacted has to be in scope, including `--connect`. `--edit` opens `$VISUAL` or `$EDITOR`. `--save-request NAME` stores the request under `requests/`.

**forms.** One normal GET, or a local file. It marks review names (`id`, `user`, `search`, `sort`, `order`, `filter`, and `*_id`) plus hidden, password, and disabled fields. Password values are blanked in anything it writes. `--save` writes raw requests for repeater. `--limit` defaults to 20. It does not send a modified request.

**silk.** Stays on the scheme, host, and port you give it. Robots paths are listed and not fetched. Defaults are depth 2 and 40 fetches. Stdout is one URL per line.

**vhost.** One connection, one GET per Host name. Names outside an active scope file are skipped. Redirects are left as they are.

**cert.** One handshake. Subject, names, issuer, and dates.

**redirect.** Stops before a hop that leaves the original hostname or scope.

**diff.** A path that exists is read from disk. A bare name such as `example.com-snare-0001.http` is read from `responses/`. A URL is one GET, and only when that host is in scope.

**dns.** Six queries, no name guessing. `--resolver` is an IP address. A CNAME with no address in the reply is marked for review.

**whois.** One in-scope domain. `--server` is an IP and is the only server queried. Without it, WebHawk asks the IANA whois server for one referral and then queries that registry once.

**jwt.** Prints the header and the claims. The signature is not checked. `--session` reads the saved Authorization value and strips a leading Bearer.

**mail.** MX, SPF, `_dmarc`, and only the DKIM selectors you pass. It does not guess selectors and does not look up the mail hosts.

**decode.** Image data and short unmarked blocks stay encoded. `--min` changes the 64-character floor.

**roost.** Read-only. Secret values stay hidden.

**clutch.** `show` takes the file name, not a path. Nothing is sent.

**blaze.** The URL has to already be in `urls.txt`. A label is a short lowercase word. Writing marks does not turn scope on.

**quill.** Each line starts with a UTC timestamp, `YYYY-MM-DD HH:MM:SSZ`.

**snare.** Listens on `127.0.0.1`. In-scope traffic is decrypted and saved. Other hosts are forwarded and left out of the files. See [Log the browser with snare](#log-the-browser-with-snare).

**skiff.** `--dry-run` prints the requests and does not connect. It needs requests, urllib3, and colorama.

Alias names: `crt-scout` is `ct`, `flowcarve` is `carve`, `lanternjaw` is `phish`, `iocaw` is `ioc`, `chromahaus` is `chroma`. The programs ship in `addons/` next to `webhawk.py`. WebHawk looks in `$WEBHAWK_ADDONS` first, then `./addons`, then `../addons`.

## Rules of engagement

Only run WebHawk against systems you own or have **written permission** to test. Unauthorized port scanning and web probing can be illegal.

Scan defaults stay small on purpose:

- common web ports only (80, 443, 8080, 8443, …)
- no full 1–65535 sweep unless you pass `--all --authorized`
- a port list longer than 4096 also requires `--authorized`
- CIDRs larger than `/24` (256 hosts) also require `--authorized`
- hard cap of 1024 expanded CIDR hosts
- `--skip-tcp` on more than 1024 ports also requires `--authorized`
- discover / mutate / params that explode past 400 paths require `--authorized`

`--i-own-this` is still accepted as an alias for `--authorized`.

## Project files

| File | Purpose |
| --- | --- |
| `webhawk.py` | Scanner, and the `webhawk` entry point when it is not installed |
| `hawk/` | Console, module loader, scope, session, and the built-in modules |
| `addons/` | pulse, crt-scout, flowcarve, Lanternjaw, IOCaw, chromahaus, urlscan, tcurl, and skiff |
| `CHANGELOG.md` | Everything new since 2.7.0 |
| `requirements.txt` | Python dependencies |
| `pyproject.toml` | Optional `pip install -e .` metadata |
| `targets.example.txt` | Sample host list |
| `agents.example.txt` | Sample User-Agent list |
| `paths.example.txt` | Sample path list |
| `headers.example.txt` | Sample custom headers |
| `http_port_probe.py` | Compatibility wrapper. Always a scan, never the shell |

## Scanner

The rest of this file is the HTTP/HTTPS mapper. `webhawk 127.0.0.1` runs it. `webhawk scan --help` prints the same flags. Closed ports never get an HTTP request unless you pass `--skip-tcp`.

```bash
webhawk doctor
webhawk 127.0.0.1
webhawk 127.0.0.1 localhost --ports 80,443,8080,8443
webhawk scan -l targets.txt --output-dir ./hawk-out
webhawk 127.0.0.1 --ports 80,443 --delay 0.3-1.0 --intel --md report.md
```

## How a scan works

1. Resolve each host and label addresses as loopback / private / public.
2. Asynchronous TCP connect scan of the selected ports (unless `--skip-tcp`).
3. For every open port, send the chosen method over HTTP and/or HTTPS for each path.
4. Classify the response: status, `Server` / `X-Powered-By`, HTML title, body snippet, tags.
5. On HTTPS, pull TLS version, subject, issuer, and expiry.
6. Optional intel: artifacts, params, headers, cookies, `security.txt`, favicon, JS, DNS, CT, banners.
7. Stream artifacts to disk and optionally write JSON / CSV / Markdown.

## Features

| Area | What you get |
| --- | --- |
| Targets | Multiple hosts, `-l` target file, small CIDR ranges |
| Ports | Common web list, `--ports`, `--ports-file`, `--range`, `--all`, `--exclude-ports` |
| Protocols | HTTP, HTTPS, or both; `--skip-tcp`; `--method GET\|HEAD\|OPTIONS\|POST` |
| Paths | Comma list or file; a leading `/` is added when missing |
| Headers | Repeatable `-H 'Name: value'` and `--headers-file` |
| User-Agents | String, file, `--random-agent`, `--rotate-agent` |
| Auth | `--auth USER:PASS` (HTTP Basic) |
| Fingerprints | Server header, title, panels, favicon mmh3 |
| Tags | `dir-listing`, `default-page`, `auth-required`, `expired-cert`, `security-txt`, product names |
| TLS | Protocol version, CN/O, issuer, notAfter, SAN, expiry flag |
| Filters | `--status`, `--grep`, `--only-live` |
| Recon extras | Discover, mutations, params, header/cookie/`security.txt` scoring, CORS, JS, DNS, CT, banners |
| Artifacts | Live URLs, page source, headers, screenshots, JSON, CSV, Markdown |
| Hygiene | Timeouts, retries, `--delay 0.5-2.0` jitter, `--proxy` |
| Safety rails | `--authorized` for wide port, path-explosion, or CIDR sweeps |

## Recon extras (opt-in)

These do **not** run unless you pass the flag (or `--intel`).

### `--intel`

Turns on `--discover --score-headers --extract-js --favicon --dns` in one switch.
Add `--cors`, `--ct`, `--banners`, `--md` yourself if you want those too.

### Artifact discovery (`--discover`)

Adds paths such as:

- `/robots.txt`
- `/sitemap.xml`
- `/favicon.ico`
- `/.well-known/security.txt`
- `/security.txt`
- `/.git/HEAD`
- `/.git/config`
- `/.env`
- `/.htpasswd`
- `/.DS_Store`
- `/backup.zip`
- `/dump.sql`
- `/phpinfo.php`
- `/server-status`

A **200/206** on a sensitive path is raised as a high finding. A 404 is just a 404.

### Path mutations (`--mutate-paths`)

For each file-like path, also request `.bak`, `.old`, `.orig`, `.zip`, `.tar.gz`,
`.sql`, `.log`, `.swp`, `~`, and anything in `--mutate-ext .inc,.dist`.

### Parameter probes (`--params` / `--params-file`)

On `/` and endpoint-like paths (`.php`, `.asp`, `.jsp`, `/api`, `/graphql`, …)
append common query names: `debug`, `test`, `admin`, `redirect`, `callback`,
`token`, `file`, … plus names from `--params-file`.

### Security header + cookie scoring (`--score-headers`)

Flags missing:

- HSTS (HTTPS only), and short `max-age` / missing `includeSubDomains`
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

Cookie flags on every `Set-Cookie`:

- missing `Secure` on HTTPS
- missing `HttpOnly`
- missing `SameSite`
- `SameSite=None` without `Secure`

Scoring runs on `/` and HTML responses so a discover sweep does not emit
20 copies of “missing CSP”.

### `security.txt` (RFC 9116)

When `/.well-known/security.txt` or `/security.txt` returns a body, WebHawk
parses `Contact`, `Expires`, `Encryption`, `Policy`, `Canonical`, `Hiring`,
and `Acknowledgments`.

Findings:

- **info** if a valid Contact / unexpired Expires is present
- **low** if Contact or Expires is missing
- **medium** if Expires is in the past

This is a file a target publishes. WebHawk reads it when a host serves one.
It does not ship a `security.txt` of its own.

Enabled whenever `--discover`, `--intel`, `--score-headers`, or `--md` causes
analysis to run.

### Favicon hash (`--favicon`)

Fetches `/favicon.ico` and computes the Shodan-style signed mmh3 of
`base64.encodebytes(body)`. The built-in table maps 60+ common products
(Jenkins, Grafana, GitLab, WordPress, Tomcat, FortiGate, BIG-IP, Jira,
Confluence, Proxmox, Zabbix, phpMyAdmin, …). Unknown hashes still print so
you can look them up later.

### JavaScript intel (`--extract-js`)

Pulls `script src`, `fetch(`, axios/jQuery calls, absolute URLs, and `/api`
style paths. Key-like assignments (`api_key=`, `secret=`, `token=`) become
high findings with the value redacted.

### CORS (`--cors`)

Sends `OPTIONS` with `Origin: https://webhawk.invalid` and `http://127.0.0.1`.

- `*` is medium
- a reflected foreign origin is high

### DNS (`--dns`) and CT (`--ct`)

DNS-over-HTTPS via Cloudflare for A, AAAA, MX, NS, TXT, CNAME, SOA, and
`_dmarc`. Certificate-transparency names from crt.sh, capped.

### Banners (`--banners`)

Reads the first bytes from TCP-open ports that did **not** speak HTTP
(SSH/FTP/SMTP/Redis-style greetings).

### Screenshots (`--screenshots DIR`)

Headless Chromium via Playwright. After `pip install -r requirements.txt`:

```bash
playwright install chromium
```

## Artifact output

| Flag | Result |
| --- | --- |
| `--save-urls FILE` | Unique live URLs, one per line, appended |
| `--save-source DIR` | Response bodies (`host_port_scheme_path.html`, …) |
| `--save-headers DIR` | Interesting response headers |
| `--screenshots DIR` | PNG captures of live pages |
| `--json FILE` | Full machine-readable result, including findings |
| `--csv FILE` | One row per live hit |
| `--md FILE` | Human-readable report grouped by host and severity |
| `--output-dir DIR` | All of the above with default names |

Bodies are truncated to `--max-body` (default 256 KiB).

## CLI reference

### Targets and ports

| Flag | Meaning |
| --- | --- |
| `targets` | IPs, hostnames, URLs, or CIDR |
| `-l FILE` | Extra targets, one per line |
| `--common` | Built-in web ports (default) |
| `--ports SPEC` | `80,443,8000-8010` |
| `--range START-END` | Inclusive range |
| `--all` | 1–65535; requires `--authorized` |
| `--ports-file FILE` | Port specs, one per line |
| `--exclude-ports SPEC` | Drop ports |
| `--authorized` | Wide-sweep acknowledgement. Alias: `--i-own-this` |
| `--skip-tcp` | HTTP(S) every selected port, no SYN scan |

### Request shape

| Flag | Meaning |
| --- | --- |
| `--paths SPEC` | Comma list **or** a paths file. Missing `/` is prepended |
| `--paths-file FILE` | Paths, one per line |
| `--method GET\|HEAD\|OPTIONS\|POST` | Default `GET` |
| `--http-only` / `--https-only` | Restrict scheme |
| `--follow-redirects` | Follow 3xx |
| `--insecure` | Skip TLS verification |
| `--no-cert` | Skip certificate metadata |
| `--host-header NAME` | Force `Host` |
| `-H HEADER` | `Name: value` (repeatable) or a headers file |
| `--headers-file FILE` | Custom headers |
| `--auth USER:PASS` | HTTP Basic |
| `--user-agent STR` | UA string **or** a file of UAs |
| `--user-agents-file FILE` | User-Agents, one per line |
| `--random-agent` | One UA for the whole scan |
| `--rotate-agent` | New UA on every request |
| `--proxy URL` | Intercepting / outbound proxy |
| `--concurrency N` | Default 256 |
| `--connect-timeout S` / `--http-timeout S` | Timeouts |
| `--retries N` | Retry timeout/connect failures |
| `--delay S` | `0.4` or jitter range `0.5-2.0` |
| `--max-body N` | Max saved body bytes |

### Recon and output

| Flag | Meaning |
| --- | --- |
| `--discover` | Artifact paths |
| `--mutate-paths` / `--mutate-ext` | Backup-style suffixes |
| `--params` / `--params-file` | Query-parameter probes |
| `--score-headers` | Missing headers + cookie flags + HSTS quality |
| `--cors` | CORS preflight |
| `--extract-js` | URLs and key-like assignments |
| `--favicon` | Favicon mmh3 + product hint |
| `--dns` | DoH record enum |
| `--ct` | crt.sh names |
| `--banners` | Non-HTTP banners |
| `--intel` | discover + headers + js + favicon + dns |
| `--status` / `--grep` / `--only-live` | Filters |
| `--save-urls` `--save-source` `--save-headers` | Raw artifacts |
| `--output-dir DIR` | live.txt + pages/ + headers/ + JSON + CSV + MD |
| `--json` `--csv` `--md` | Reports |
| `--screenshots DIR` | Playwright captures |
| `--quiet` `--version` | Banner / version |

## List file formats

Blank lines and `#` comments are ignored.

`targets.txt`

```
127.0.0.1
localhost
app.internal.example
```

`paths.txt`

```
/
robots.txt
admin
```

`admin` becomes `/admin`.

`agents.txt`

```
WebHawk/2.15.0 (coffee-powered)
Mozilla/4.0 (PSP (PlayStation Portable); 2.00)
```

`headers.txt`

```
Accept-Language: en-US,en;q=0.8
X-Forwarded-For: 127.0.0.1
```

`params.txt`

```
debug
verbose
reset
```

## Examples

```bash
# Quiet lab box, dump everything
webhawk 127.0.0.1 --ports 80,443,8080 --output-dir ./hawk-out

# Authorized recon pack
webhawk app.internal --ports 80,443 --https-only --insecure \
    --delay 0.4-1.2 --intel --cors --ct --banners --md hawk.md

# Custom lists
webhawk 127.0.0.1 --http-only --ports 8765 \
    --user-agent agents.example.txt --rotate-agent \
    --paths paths.example.txt \
    --headers-file headers.example.txt \
    --mutate-paths --params

# Skip TCP, HTTP only
webhawk 127.0.0.1 --ports 80,443,8080 --skip-tcp --only-live

# Full-port sweep you own
webhawk 127.0.0.1 --all --authorized --only-live --save-urls live.txt
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Finished |
| 2 | Bad arguments / safety rail tripped |
| 130 | Interrupted |

DNS failures on one host do not abort the rest of the list.

## Limitations

- HTTP speaker check first, not a general-purpose port scanner.
- `--all` and `--discover` + `--mutate-paths` + `--params` get loud. Stay in scope.
- Favicon hints are a lookup table, not a guarantee.
- `security.txt` parsing is RFC 9116 field extraction, not a compliance audit.
- Cookie scoring looks at `Set-Cookie` attributes only; it does not replay sessions.
- Page source is a single path, truncated to `--max-body`, not a crawl.
- Playwright needs `playwright install chromium` after pip.

## License / use

Provided as-is for defensive and authorized testing. You are responsible for
staying inside your scope and local law.
