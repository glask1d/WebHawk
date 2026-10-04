# Lanternjaw

<p align="center">
  <img src="https://github.com/user-attachments/assets/dae572e2-28cb-4be1-92ae-4d055e4a41c5" alt="Lanternjaw" width="280">
</p>

```
                 .--------------------------------------.
                 |   L A N T E R N J A W                |
                 |   the lure hunts back                |
                 '--------------------------------------'
                              \   *
                               \ /|
                          ______\ |___________
                     ____/                 \____
                  __/    \    (o)   (o)    /    \__
                 /        \      <JAW>    /        \
                |  phish  '.___hunt___.'   intel    |
                 \______________|__________________/
                                |
        phishunt.io   ·   CC0   ·   passive unless you ask for deep
```

**Lanternjaw** is a colorful command-line hunter for the public
[phishunt.io](https://phishunt.io/api/) phishing-intelligence API.

An anglerfish hunts with a light. Phishing kits hunt with a lure.
Lanternjaw points the light back at the lure: active suspicious domains,
the brands they impersonate, the networks that host them, and the clusters
that share infrastructure.

phishunt collects this from Certificate Transparency, Google Safe Browsing,
OpenPhish, PhishTank, TweetFeed, and urlscan.io, then adds IP, ASN, country,
and TLS issuer. The open API needs no key. Data is CC0 and refreshed about
once an hour. The documented ceiling is 10 requests/second per IP.

This tool queries that API. It does not open the suspicious sites, run them,
or decide they are guilty. False positives happen. A source flag of `false`
means "not flagged when we checked," not "clean." Scores are heuristics, not
probabilities. Campaign labels are shared-infrastructure groupings
(`possible campaign`, `suspected cluster`), never an actor name.

API reference: https://phishunt.io/api/

## Preview
![lanternjaw](https://github.com/user-attachments/assets/a0463de7-d2f9-4eed-889b-c4f4acb3cb7b)

## Install

Python 3.10 or newer.

```bash
cd lanternjaw
python3 -m pip install -r requirements.txt
chmod +x lanternjaw.py
```

Needs `requests` and `rich`.

## Quick start

```bash
# morning picture: brands, countries, networks, hottest, newest
python3 lanternjaw.py pulse

# one brand, only rows phishunt has a screenshot or urlscan hit for
python3 lanternjaw.py hunt --company paypal --tier verified

# passive score of a URL you were sent. The target is not contacted.
python3 lanternjaw.py analyze https://amazon-secure-login.example.com/signin

# one detection: card, overlapping infra, RDAP, geo
python3 lanternjaw.py inspect 241d3520-f3ee-4bba-ae44-2fa95c51305c

# clusters that share a cert, an IP, a favicon, ...
python3 lanternjaw.py campaigns --status active --min-size 3
python3 lanternjaw.py campaign 6103d8e3eab3
```

Screen output defangs URLs and IPs (`hxxps://`, `[.]`) so a paste into chat
or a slip of the mouse does not open a kit. Pass `--live` when you need the
raw text. `--json` writes the machine payload to stdout and leaves the
tables on stderr.

## What you can ask it

| Command | What it does |
| --- | --- |
| `about` | Pipeline, sources, and the endpoint map. No network. |
| `pulse` | Dashboard over the active feed, or a filtered slice. |
| `hunt` | Active detections. Every domains-API filter, plus local score and source filters. |
| `search` | Free text across URL, domain, and IP (`/api/v1/search.json`). |
| `analyze` | Passive URL shape score. phishunt does not connect to the target. |
| `deep` | **Active.** phishunt fetches the URL. Token and `--yes` required. |
| `campaigns` | List possible campaigns / suspected clusters. |
| `campaign` | One cluster by stable `key` (the numeric id changes every rebuild). |
| `related` | Other detections that share infrastructure with a uuid. |
| `enrich` | RDAP dates/registrar and IP geolocation for a uuid. |
| `brand` | Curated brand card and the live count. |
| `cert` | TLS issuer card and the live count. |
| `feed` | Full dump: `json`, `csv`, `txt`, or STIX 2.1. |
| `blocklist` | Pi-hole, hosts, Adblock, dnsmasq, unbound, or RPZ. |
| `pivot` | Group a slice by `ip`, `asn`, `org`, `cert`, `country`, `company`, or `registrar`. |
| `triage` | Hottest rows, score first, then how many feeds agreed. |
| `inspect` | Feed card + related + enrich for one uuid. |
| `match` | Check your own domain, URL, or IP list against the active feed. |
| `watch` | Poll for detections newer than a timestamp. |
| `snapshot` | Save the active feed. |
| `diff` | Uuids that appeared or disappeared since a snapshot. |
| `report` | Markdown brief you can drop into a ticket. |
| `self-test` | Offline checks. No network. |

### Filters

These are sent to `/api/v1/domains` when you set them:

```text
--company paypal      --since 2026-09-01     --contains login
--tier verified       --asn AS13335          --org "Cloudflare, Inc."
--registrar "..."     --cert "Let's Encrypt" --country Germany
--ip 203.0.113.10
```

`org`, `registrar`, `cert`, `country`, and `ip` are exact, spelled the way
the API spells them. `contains` is 3–80 characters of letters, digits, or
`-._`.

These run locally, after the rows are in hand:

```text
--verdict high        --min-score 40         --min-sources 2
--sort first_seen|score|sources|brand
```

`hunt` shows 25 rows unless you pass `--limit` or `--all`. `--export file.csv`
writes that same set (`.json`, `.csv`, or `.txt`). Export files contain
**live** indicators, because a blocker or a SIEM cannot eat defanged text.
`--offset` is a raw API page and skips the full scan.

The active feed is about a megabyte. Lanternjaw caches it for 10 minutes
under `~/.cache/lanternjaw/feed.json` (or `$XDG_CACHE_HOME`). `--fresh`
reloads it. `diff` always reloads.

## Analyst loops

**Morning sweep**

```bash
python3 lanternjaw.py pulse --fresh
python3 lanternjaw.py triage --min-sources 2 --limit 30
python3 lanternjaw.py pivot asn --min-count 4
```

**A brand your SOC cares about**

```bash
python3 lanternjaw.py brand paypal
python3 lanternjaw.py hunt --company paypal --tier verified --sort score
python3 lanternjaw.py report --company paypal --out paypal.md
```

**A URL from a mailbox**

Prefer a bare domain if the link contains a token or a password. phishunt
logs the URL you submit. The passive call does not connect to the host.
Suspicious unknown domains may be queued on their side for the normal pipeline.

```bash
python3 lanternjaw.py analyze login.brand.example
```

The panel separates three different answers on purpose:

- `url risk` is the shape of the string alone.
- `stored verdict` is phishunt's score for a row it already had. Different scale. Do not treat the two numbers as the same tier.
- `adjudicated verdict` is the one field they tell you to read.

**Proxy or DNS logs**

One indicator per line. `#` comments are ignored. Defanged lines are accepted.

```bash
python3 lanternjaw.py match /var/log/suspect-hosts.txt --fresh --fail-on-hit
echo "paypal-login.example" | python3 lanternjaw.py match - --json
```

Exit status is `1` only when `--fail-on-hit` finds something, so a cron job
can mail on a match. A bare TLD like `com` will not light up the whole feed.

**What changed since yesterday**

```bash
python3 lanternjaw.py snapshot --fresh --out today.json
# tomorrow
python3 lanternjaw.py diff today.json --company microsoft
```

`diff` filters the snapshot and the fresh feed the same way, so `--company`
does not mark every other brand as gone. `--tier` is skipped there: a saved
row does not say whether phishunt had a screenshot.

**A blocklist for the resolver**

Upstream wants these refreshed on a timer (15 minutes or faster is their
suggestion; the detection pipeline itself is hourly).

```bash
python3 lanternjaw.py blocklist domains --out /etc/pihole/phishunt-domains.txt
python3 lanternjaw.py blocklist dnsmasq --out /etc/dnsmasq.d/phishunt.conf
```

| Format | Consumer |
| --- | --- |
| `domains` | Pi-hole adlist, one registrable domain per line |
| `hosts` | `/etc/hosts`-style |
| `adblock` | uBlock Origin / AdGuard |
| `dnsmasq` | `address=` directives |
| `unbound` | pfSense / OPNsense |
| `rpz` | BIND / Knot response policy |

Shared platforms (Blogspot, GitBook, and the like) stay at the phishing
hostname. The list does not block the whole provider.

**Sit on the firehose**

```bash
python3 lanternjaw.py watch --company coinbase --interval 300 --log coinbase.jsonl
```

The first poll uses "now", so you see what arrives after you start.
`--since 2026-09-27T00:00:00Z` looks backward. Ctrl-C stops it.

## Campaigns, related infra, enrichment

`campaigns --status active` keeps clusters that still have a live member.
`confidence_score` of at least 0.70 is labeled `possible campaign`; 0.40 to
0.70 is `suspected cluster`. Weaker clusters are not in the API at all.

Use the hex `key` in links and in `campaign`. A bookmarked numeric id can
still resolve for about 180 days, then it will not. An archived key returns
200 with `"state": "archived"` and a thinner object, not a 404. `data_status`
of `stale` or `missing` means the nightly correlation job did not rebuild, so
an empty list is not the same thing as "no campaigns."

```bash
python3 lanternjaw.py related 241d3520-f3ee-4bba-ae44-2fa95c51305c --min-score 40
python3 lanternjaw.py enrich 241d3520-f3ee-4bba-ae44-2fa95c51305c
python3 lanternjaw.py cert "Google Trust Services"
```

`enrich` is WHOIS/RDAP plus ipinfo, cached by phishunt for about a day.
Either half can come back with an `error` and still include the fields that
did resolve. Registrar strings are not a person's identity.

CSV/TXT campaign export promises live enrichment, so phishunt returns 404
for those formats on an archived key. JSON still works.

## Feeds and STIX

```bash
python3 lanternjaw.py feed json            # dashboard of the full active set
python3 lanternjaw.py feed stix --out phishunt-bundle.json
python3 lanternjaw.py feed txt --out urls.txt
```

`/feed.json` is a flat array. `/feed.txt` is one URL per line. The STIX 2.1
bundle has one indicator per detection. Confidence on each indicator is that
row's own score, not one number stamped on the whole file. Marking is
TLP:CLEAR.

## Deep analysis

`GET /api/v1/analyze/deep` is the only call in this client that is not open.

phishunt fetches the URL (HTTP response, certificate, RDAP, nameservers,
GeoIP) through their proxy, then re-scores it. That takes roughly 5–15
seconds, spends a shared budget of 50 analyses per UTC day, and only one
analysis can run at a time. There is no browser and no screenshot. A low
score often means "not fully evaluated." Read `analysis_failures` and the
per-signal errors before you treat a low number as reassuring.

```bash
export PHISHUNT_DEEP_TOKEN=...          # or pass --token
python3 lanternjaw.py deep https://example.com --yes
```

Without `--yes` the command refuses to run. Do not submit URLs that contain
passwords, session tokens, or other secrets. The URL is transmitted and logged.
Lanternjaw never fetches the suspicious host itself.

## Output, color, and exit codes

```text
-q, --quiet       banner off
-v, --verbose     print each HTTP status on stderr
--live            raw URLs and IPs on screen
--fresh           ignore the feed cache
--timeout 60      seconds
--json            payload on stdout
```

Source column, left to right: **G**oogle Safe Browsing, **O**penPhish,
**P**hishTank, **T**weetFeed, **U**rlscan. Bright means that source flagged
the row. Dim means it did not.

| Exit | Meaning |
| --- | --- |
| 0 | Finished, or `match` found nothing |
| 1 | Network, rate limit, or other API failure. `match --fail-on-hit` also uses 1 |
| 2 | The request was rejected or the id is unknown (HTTP 400 or 404) |
| 130 | Ctrl-C |

Rate limits return 429. The client sleeps on a short `Retry-After` and gives
up if the server asks for more than 90 seconds (deep-analysis budget resets
at UTC midnight, and waiting that out is not useful).

## Honesty, in one place

- The suspicious URL is someone else's website. Don't browse it from a normal browser to "see if it's real."
- phishunt's population drops high-confidence parked domains and hostname-intent clones. PaaS kits (`pages.dev`, `vercel.app`, `github.io`, and similar) stay in.
- `pulse` counts punycode hosts, shared-platform suffixes, and credential-ish path tokens (`login`, `verify`, `wallet`) as shape, not as proof.
- IP geolocation is ipinfo.io, via phishunt. Some rows also carry a SANS ISC DShield `sans_score` from insertion time, under CC BY-NC-SA 4.0, attributed to SANS Internet Storm Center / DShield.
- Terms and the best-effort notice live at https://phishunt.io/tos/ and https://phishunt.io/api/.

## Layout

```text
lanternjaw.py       the client
requirements.txt    requests, rich
README.md           you are here
```

`python3 lanternjaw.py self-test` checks defanging, source flags, and
matching without calling the network.
