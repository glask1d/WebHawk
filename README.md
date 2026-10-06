<p align="center">
  <img src="https://github.com/user-attachments/assets/d4e3b632-521f-4030-9a91-86a6192f7404" alt="WebHawk — HTTP / HTTPS attack-surface mapper" width="100%">
</p>

# WebHawk

**Version 2.7.0** — HTTP/HTTPS attack-surface mapper for **authorized** assessments.

WebHawk finds ports that actually speak HTTP or HTTPS, fingerprints what is
listening, and can write live URLs, page source, and a findings report to disk.
It is meant for lab boxes, your own servers, and scoped engagements — not for
scanning the internet.

The default command is still that scan: `webhawk 127.0.0.1`. In a terminal,
`webhawk` with no arguments opens a console where you load pulse, crt-scout,
flowcarve, and the other modules. From a script, `webhawk pulse urls.txt`
runs that module once and exits.

```bash
python webhawk.py 127.0.0.1 lab.local
python webhawk.py -l targets.txt --save-urls live.txt --save-source pages/
python webhawk.py app.internal --ports 80,443 --intel --cors --md hawk.md
```

## Preview
![wh-1](https://github.com/user-attachments/assets/2e47e7f7-09ea-41a5-9eea-de8291f369ae)
![wh-2](https://github.com/user-attachments/assets/589ca1d1-c900-45bc-b951-1edd73458340)

## Commands

| Command | What it does |
| --- | --- |
| *(no arguments, in a terminal)* / `console` | Interactive console. `use` selects a module, `show options` lists its flags, `set` saves them, `run` executes it. |
| *(default)* / `scan` | The HTTP/HTTPS mapper. Flags are listed by `webhawk scan --help`. |
| `pulse`, `ct`, `carve`, `phish`, `ioc`, `chroma`, `urlscan`, `tcurl` | Run that module once and exit. `webhawk <module> --help` prints its flags. |
| `scope`, `robots`, `repeater` | Built-in scope list, robots and sitemap URLs, and a request repeater. |
| `modules` | Built-in commands, plus which module programs are on disk. |
| `doctor` | Python version, required packages, optional packages, and the `curl` / `torsocks` / `tor` programs `tcurl` uses. |
| `examples` | Copy-paste scans and shell-setup lines. |
| `completion bash\|zsh` | Completion script. Write it to your shell's completion directory. |
| `version` | Print the version. `--version` and `-V` do the same. |
| `help` | This guide. `webhawk help scan` prints every scan flag. `webhawk help pulse` describes that module. |

## Console

Opening `webhawk` in a terminal prints one of five ASCII banners and a short command list. Each start, and each `banner` command, picks a different one. `help` prints the rest.

Tab completes the word at the cursor: commands, module names, option names, choices, and file paths. Up and down recall recent lines. History is kept in `~/.local/share/webhawk/history` (override with `WEBHAWK_HISTORY`). A line that contains a token, password, or secret is left out of that file. `search liveness` lists modules whose name or description matches.

```text
webhawk
webhawk > use pulse
webhawk pulse > show options
webhawk pulse > set FILE urls.txt
webhawk pulse > set FOLLOW_REDIRECTS true
webhawk pulse > run
webhawk pulse > back
webhawk > use ct
webhawk ct > run example.com -c -o live.txt
webhawk ct > exit
```

Option names are the argument destination in uppercase. Pulse's URL file is `FILE`. `set FILE=urls.txt` is the same as `set FILE urls.txt`. `true`, `yes`, `on`, and `1` turn a switch on. `unset FILE` forgets one value. `unset all` clears the module you have selected.

Saved values stay on that module across `back` and later `use`. They fill whatever you leave off the next `run`. Arguments you type on `run` win, so `run other.txt` uses `other.txt` even when `FILE` is set. `run urls.txt --follow-redirects` still works on its own.

`run --help` prints the selected module's flags. Typing the module name at the prompt runs it immediately: `pulse urls.txt`. `exit` leaves. Ctrl-C stops the module and returns to the prompt.

`phish` and `chroma` have subcommands. `show options` lists them. `set COMMAND hunt` then `show options` lists that command's flags. `deep` and `download` stay available only after you select them.

`tcurl` fetches a URL with curl through Tor:

```text
webhawk tcurl > set URL example.com
webhawk tcurl > set NO_PAGER true
webhawk tcurl > run -I
```

Curl flags that take a value go in `EXTRA`, so the value stays with the flag:

```text
webhawk tcurl > set EXTRA -A 'WebHawk' -H 'Accept: application/json'
webhawk tcurl > run
```

`tcurl` needs `curl`, `torsocks`, and a Tor daemon on `127.0.0.1:9050`. `webhawk doctor` lists those three as optional.

## Scope, robots, and repeater

`scope` is the allow-list for an engagement. It lives in `./.webhawk`, or in `$WEBHAWK_SCOPE` when that is set. Loopback is always allowed. Other hosts wait until you add them. A domain includes its subdomains. `*.example.com` is subdomains only. An address matches that address or a CIDR.

```bash
webhawk scope init
webhawk scope add app.internal '*.lab.internal' 10.1.0.0/16
webhawk scope allow https://www.app.internal/admin
webhawk scope import-urls found.txt
webhawk scope urls
```

`import-urls` keeps lines that already contain `://` and whose host is in scope. `urls` prints `.webhawk/urls.txt`. Point pulse at that file:

```bash
webhawk pulse .webhawk/urls.txt
```

`robots` reads a saved robots.txt or sitemap and prints one URL per line. Relative paths need `--base`. When a scope file exists, in-scope URLs are printed and new ones are appended to the URL list. `--no-workspace` prints every URL and leaves that list unchanged. `--fetch` requests one in-scope URL (loopback needs no scope entry) and follows a sitemap it names. A redirect onto a host outside scope is discarded. The URL list is stdout. The short summary is stderr, so this stays a clean list:

```bash
webhawk robots robots.txt sitemap.xml --base https://app.internal
webhawk robots --fetch http://127.0.0.1:8080/robots.txt
```

`repeater` loads a raw HTTP request, applies your edits, then sends that copy. `--print` writes the edited request and returns before any connection. The host that is contacted has to be in scope. `--connect` delivers the request to `HOST` or `HOST:PORT` and keeps the Host header. `--edit` opens `$VISUAL` or `$EDITOR` after the other edits. `--save-request NAME` stores that request under `.webhawk/requests/`.

```bash
webhawk repeater captured.http --method POST --path /api/v2 --header 'X-Test: yes' --body '{"ok":true}' --print
webhawk repeater captured.http --edit
webhawk repeater captured.http --connect 127.0.0.1:8080
```

The same tools from the shell:

```bash
webhawk pulse urls.txt --follow-redirects
webhawk ct example.com -c -o live.txt
webhawk carve capture.har --unique
webhawk tcurl --help
webhawk scope init
webhawk repeater captured.http --print
```

`crt-scout` is `ct`. `flowcarve` is `carve`. `lanternjaw` is `phish`. `iocaw` is `ioc`. `chromahaus` is `chroma`.

A host that is literally named like a command needs an explicit scan:

```bash
webhawk scan modules
webhawk -- pulse
```

pulse, ct, carve, phish, ioc, chroma, urlscan, and tcurl ship in `addons/` next to `webhawk.py`. WebHawk looks in `$WEBHAWK_ADDONS` first, then `./addons`, then `../addons`.

A positional argument that is an existing file is not scanned as a hostname. Put host lists on `-l`.

## Rules of engagement

Only run WebHawk against systems you own or have **written permission** to
test. Unauthorized port scanning and web probing can be illegal.

Defaults stay small on purpose:

- common web ports only (80, 443, 8080, 8443, …)
- no full 1–65535 sweep unless you pass `--all --authorized`
- a port list longer than 4096 also requires `--authorized`
- CIDRs larger than `/24` (256 hosts) also require `--authorized`
- hard cap of 1024 expanded CIDR hosts
- `--skip-tcp` on more than 1024 ports also requires `--authorized`
- discover / mutate / params that explode past 400 paths require `--authorized`

`--i-own-this` is still accepted as an alias for `--authorized`


## Install

Python 3.10+ recommended.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium        # needed for --screenshots
chmod +x webhawk.py
python webhawk.py doctor
python webhawk.py --version
```

Editable install, optional. This puts a `webhawk` command on `PATH`:

```bash
pip install -e .
```

`requirements.txt` currently includes:

- `rich`
- `httpx`
- `playwright`
- `requests` (phish and ioc)
- `aiohttp` (ct)

Install on PATH:

```bash
chmod +x ~/tools/webhawk/webhawk.py
sudo ln -sf ~/tools/webhawk/webhawk.py /usr/local/bin/webhawk
```

## Project files

| File | Purpose |
| --- | --- |
| `webhawk.py` | Scanner, and the `webhawk` entry point |
| `hawk/` | Command shell: router, console, module options, loader, `doctor`, completion, and scope, robots, and repeater |
| `addons/` | pulse, crt-scout, flowcarve, Lanternjaw, IOCaw, chromahaus, urlscan, and tcurl |
| `requirements.txt` | Python dependencies |
| `pyproject.toml` | Optional `pip install -e .` metadata |
| `images/wh-banner.jpg` | README header art |
| `images/webhawk.png` | Preview image |
| `targets.example.txt` | Sample host list |
| `agents.example.txt` | Sample User-Agent list |
| `paths.example.txt` | Sample path list |
| `headers.example.txt` | Sample custom headers |
| `http_port_probe.py` | Compatibility wrapper. Always a scan, never the shell |

## Quick start

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

Closed ports never get an HTTP request unless you pass `--skip-tcp`.

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
WebHawk/2.7.0 (coffee-powered)
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
