# 🔍 crt-scout — Blazing-fast subdomain discovery & reconnaissance

A modern Python rewrite of certificate transparency subdomain enumeration with async HTTP(S) live-checking, wordlist generation, and beautiful colored output.

## ⚡ Features
• Async/concurrent checking — 50+ workers for lightning speed
• Live host validation — HTTP/HTTPS probing with status codes  
• Smart wordlist extraction — Pull unique subdomain prefixes for fuzzing
• Progress indicators — Real-time progress during checks
• Colored output — Green for live, red for dead, clean formatting
• Flexible output — Save to file or stdout, show/hide dead hosts

## 🚀 Usage
  python crt-scout.py x.com -c -o live.txt -w words.txt

## 📦 Requirements: Python 3.8+, aiohttp
  pip3 install -r requirements

## ➡️ Options

| Flag | Description |
|------|-------------|
| `-c, --check` | Check which subdomains are alive |
| `--https-only` | Only probe HTTPS (skip HTTP) |
| `-o FILE` | Save results to file |
| `-w FILE` | Extract subdomain prefixes to wordlist |
| `--workers N` | Concurrent workers (default: 50) |
| `--timeout N` | Connection timeout seconds (default: 5) |
| `--show-dead` | Include dead hosts in output |
| `-q, --quiet` | Suppress progress output |



# ⚠️ This is 100% vibecoded slop, if you run into any issues hit me up on X @glask1d :DDD
