# Pulse

Concurrent URL liveness checker with color-grouped status tables.

Point it at a text file of URLs. Pulse hits them in parallel, paints the results
by status family (2xx / 3xx / 4xx / 5xx / unreachable), and optionally follows
redirects so you can see where a 301 actually lands.

```
python pulse.py urls.txt
python pulse.py urls.txt --follow-redirects --show-redirects
```

![pulse](images/pulse1.png)

![pulse](images/pulse2.png)

## Requirements

- Python 3.10+
- [httpx](https://www.python-httpx.org/)
- [rich](https://rich.readthedocs.io/)
- optional: `h2` for HTTP/2 (Pulse uses HTTP/1.1 if it is not installed)

```bash
python -m pip install -r requirements.txt
```

## Input file

One URL per line. Blank lines and `#` comments are ignored. Duplicates are
dropped. A missing scheme is treated as `https://`.

```
# production
https://example.com
example.org

# expected failures
https://httpbin.org/status/404
https://this-host-does-not-exist.invalid
```

Use `-` as the file argument to read from stdin:

```bash
cat urls.txt | python pulse.py -
```

A starter list ships as `urls.example.txt`.

## Usage

```text
python pulse.py FILE [options]
```

| Flag | Default | What it does |
| --- | --- | --- |
| `-f`, `--follow-redirects` | off | Follow 3xx responses and report the **final** status |
| `--show-redirects` | off | Print the full redirect chain when one exists |
| `-c`, `--concurrency N` | `20` | Max parallel requests |
| `-t`, `--timeout SEC` | `10` | Per-request timeout |
| `-r`, `--retries N` | `1` | Extra attempts after a network failure |
| `-A`, `--user-agent STR` | `Pulse/1.0` | Override the User-Agent |
| `-k`, `--insecure` | off | Skip TLS certificate verification |
| `--only FAMILIES` | all | Only print these families or codes (`2xx,error` or `404,500`) |
| `--json PATH` | — | Write the full result set as JSON |
| `--csv PATH` | — | Write the full result set as CSV |

### Examples

```bash
# default: 3xx reported as-is (the host answered)
python pulse.py urls.txt

# resolve the destination, and print every hop
python pulse.py urls.txt --follow-redirects --show-redirects

# hammer a big list, dump both exports
python pulse.py urls.txt -c 40 --timeout 8 --retries 2 \
    --json results.json --csv results.csv

# only the bad news
python pulse.py urls.txt --only 4xx,5xx,error

# sites with expired / self-signed certs
python pulse.py urls.txt --insecure
```

## How results are grouped

| Family | Color | Meaning |
| --- | --- | --- |
| **2xx** | green | Success. Counted live. |
| **3xx** | cyan | Redirect. Counted live *unless* you passed `--follow-redirects` (then the final code decides). |
| **4xx** | yellow | Client error (404, 403, …). Down. |
| **5xx** | red | Server error. Down. |
| **error** | magenta | DNS, TLS, timeout, connection refused. Down. |

Each row shows status code, latency in milliseconds, the original URL, the
final URL or error string, and the response `Content-Type`.

A summary panel at the bottom totals live vs down, counts per family, average
latency, and wall-clock time.

## Exit codes

| Code | When |
| --- | --- |
| `0` | Every URL was 2xx, or an unfollowed 3xx |
| `1` | At least one 5xx or unreachable host |
| `2` | Bad CLI arguments |
| `130` | Interrupted with Ctrl+C |

4xx responses are printed and counted as down in the summary, but they do
**not** flip the process exit code. That keeps “the site is up, the path is
wrong” distinct from “the box is on fire.” Use `--only 4xx` if you want to
review those separately.

## Exports

JSON shape:

```json
{
  "generated_at": "2026-09-09T00:00:00+00:00",
  "count": 2,
  "results": [
    {
      "url": "https://example.com",
      "ok": true,
      "status": 200,
      "reason": "OK",
      "family": "2xx",
      "elapsed_ms": 48,
      "final_url": "https://example.com",
      "content_type": "text/html",
      "error": "",
      "redirects": ""
    }
  ]
}
```

CSV columns: `url`, `ok`, `status`, `reason`, `family`, `elapsed_ms`,
`final_url`, `content_type`, `error`, `redirects`.

## Notes

- Checks are `GET`s, not `HEAD`s. Some CDNs and app servers lie on HEAD.
- Redirects are capped by httpx’s default hop limit. `--follow-redirects` plus
  a loop shows up as `too many redirects` in the error family.
- `--insecure` is for lab certs. Do not point it at anything you need to trust.
- HTTP/2 is used automatically when the `h2` package is installed.

## License

Use it, fork it, rename it again. No warranty — if a URL is down, that is
between you and the server.
