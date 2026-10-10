```text
                         .
                        /|\
                       / | \
                      /  |  \
                     /   |   \
               _____/____|____\_____
            __|                     |__
       ~~~~|                          |~~~~
          '~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
             ~      ~      ~      ~

  ____    _  __    ___   _____    _____
 / ___|  | |/ /   |_ _| |  ___|  |  ___|
 \___ \  | ' /     | |  | |_     | |_
  ___) | | . \     | |  |  _|    |  _|
 |____/  |_|\_\   |___| |_|      |_|
Skiff v2.0.0
a small boat for a wide search
```

# Skiff

**Skiff** is a small HTTP fuzzer for security testing, endpoint discovery, and API exploration. Put `FUZZ` where a word from the wordlist should land. It supports raw requests, transformations, threads, and response filters. Startup prints a colored sailing skiff: yellow mast, white and cyan sails, a cyan hull, and blue water. The wordmark is cyan, green, yellow, magenta, and red.

## Table of Contents
- [Features](#features)
- [Output](#output)
- [Setup & Installation](#installation)
- [Notes](#notes)


## Features

Skiff 2.0 is the renamed fuzzer. The placeholder is `FUZZ`, and the script is `skiff.py`. Each feature below has an example command.

### 1. Target URL Fuzzing (`-u/--url`)
Replace the `FUZZ` placeholder in a URL with words from a wordlist to discover endpoints.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst
```

### 2. Wordlist Support (-w/--wordlist)
Specify a wordlist file for fuzzing (required).
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst
```

### 3. Concurrent Threads (-t/--threads)
Set the number of concurrent threads for faster fuzzing (default: 10).
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst -t 20
```

### 4. HTTP Method Selection (-m/--method)
Choose the HTTP method (e.g., GET, POST) for requests (ignored with --request-file).
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst -m POST
```

### 5. Filter Status Codes (-fc/--filter-code)
Exclude responses with specified status codes (comma-separated). Spaces around commas are ignored.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst -fc 404,500
```

### 6. Filter Response Size (-fs/--filter-size)
Exclude responses with these content lengths in bytes. `0` is a real size, and the flag accepts a comma-separated list.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst -fs 0,1230
```

### 7. Output File (-o/--output)
Save results to a file.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst -o results.txt
```

### 8. Colored Output (--color/--no-color)
Hits are colored by status: green for 2xx, cyan for 3xx, yellow for 4xx, and red for 5xx. The matched payload is magenta. Color turns on when stdout is a terminal, `--color` forces it, and `--no-color` or a non-empty `NO_COLOR` environment variable turns it off. Saved files never contain color codes.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst --no-color
```

### 9. Custom Headers (-H/--headers)
Add custom HTTP headers (repeatable).
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst -H "Authorization: Bearer token123"
```

### 10. Custom Cookies (-c/--cookies)
Add custom cookies (semicolon-separated).
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst -c "session=abc123;user=admin"
```

### 11. Follow Redirects (--follow-redirects)
Follow HTTP redirects in responses.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst --follow-redirects
```

### 12. Proxy Support (-p/--proxy)
Route requests through a proxy (e.g., Burp Suite).
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst -p http://127.0.0.1:8080
```

### 13. Base64 Encoding (--base64)
Base64-encode each word before fuzzing.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst --base64
```

### 14. Custom User-Agent (--user-agent)
Set a custom User-Agent (default: Skiff v2.0.0). In URL mode the value may contain `FUZZ`.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst --user-agent "Mozilla/5.0"
```

### 15. Raw HTTP Request File (--request-file)
Use a raw HTTP request file with `FUZZ` placeholders instead of `-u`/`-m`. Placeholders in the request line, headers, and body are all replaced. `-u` only supplies the scheme (and the host if the file has none). `Content-Length` in the file is ignored and recalculated.
```bash
python3 skiff.py --request-file login.req -w wordlist.lst
```

### 16. Requests Per Second Limiting (--rps)
Limit requests per second to avoid overwhelming servers.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst --rps 5
```

### 17. Wordlist Encoding (--encoding)
Specify wordlist file encoding (default: utf-8, falls back to latin-1).
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst --encoding latin-1
```

### 18. File Extensions (-x/--extensions)
Append extensions (comma-separated) to each word.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst -x php,html
```

### 19. Verbose Mode (-v/--verbose)
Show all responses, including 404s (default: hide 404s).
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst -v
```

### 20. Response Body Regex Filtering (--match-regex)
Filter responses where the body matches a regex pattern.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst -x php --match-regex "Hello"
```

### 21. Request Timeout (--timeout)
Set a custom request timeout in seconds (default: 5.0).
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst --timeout 2.0
```

### 22. Word Transformations (--transform)
Add variants of each word: `upper`, `lower`, `cap`, `reverse`, `append_<string>`, or `prepend_<string>`. Each transform is applied to the original word, not chained onto the previous variant.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst --transform upper,append_123
```

### 23. Randomized Word Order (--randomize)
Shuffle the wordlist to randomize request order.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst -v --randomize
```

### 24. Multiple FUZZ Placeholders (--multi-fuzz)
`same` (the default) puts the current payload in every `FUZZ`. `combo` tries the cartesian product across every `FUZZ`, in file order for a request file and in URL, header, cookie, then body order otherwise. Payloads placed in a URL or request line are percent-encoded unless you pass `--no-encode`. Combo mode stops above 2,000,000 requests.
```bash
python3 skiff.py --request-file login.req -w wordlist.lst --multi-fuzz combo
```

### 25. Response Header Filtering (--match-header)
Require response headers (repeatable). Every listed header must be present. The name match is case-insensitive, and the value match is a substring, so `text/html` matches `text/html; charset=utf-8`.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst -x php --match-header "Content-Type:text/html"
```

### 26. Silent Mode (--silent)
Suppress non-result output (progress, warnings, summary, ASCII art) for scripting. Hits stay on stdout. A scan that cannot connect still prints an error and exits 1.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst -x php --silent
```

### 27. SSL Verification Control (--ignore-ssl/--no-ignore-ssl)
Ignore SSL certificate verification (default) or enforce it.
```bash
python3 skiff.py -u https://127.0.0.1/FUZZ -w wordlist.lst --no-ignore-ssl
```

### 28. Match Status Codes (-mc/--match-code)
Show only these status codes. This overrides the default of hiding 404 responses. `-v` also shows 404s, without turning off your other filters.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst -mc 200,301,302
```

### 29. Match Or Filter Size, Words, And Lines
`-ms/--match-size` keeps only those body sizes. `-fw/--filter-words`, `-mw/--match-words`, `-fl/--filter-lines`, and `-ml/--match-lines` do the same for word counts and line counts. All of them accept comma-separated numbers, including `0`.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst -mw 3 -fl 0,1
```

### 30. Filter Body Regex (--filter-regex)
Hide responses whose body matches a regex. `--match-regex` still shows only bodies that match.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst --filter-regex "page not found"
```

### 31. Inline Request Body (-d/--data)
Send a body without a raw request file. The method defaults to POST when `--data` is set. `FUZZ` in the body is a placeholder.
```bash
python3 skiff.py -u http://127.0.0.1/login -d "name=FUZZ&pass=password" -w users.txt -mc 200
```

### 32. Prefix, Suffix, And Extra Transforms (--prefix/--suffix/--transform)
`--prefix` and `--suffix` are literal text added to each payload. `--transform` still adds variants of the original word (`upper`, `lower`, `cap`, `reverse`, `append_TEXT`, `prepend_TEXT`). It does not chain them: `upper,append_1` produces `WORD` and `word1`.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst --prefix admin_ --transform reverse,upper
```

### 33. Delay (--delay)
Wait at least this many seconds between request starts. If you also set `--rps`, the slower of the two limits is used. Fractional `--rps` values work.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst --delay 0.2
```

### 34. Output Formats (-of/--output-format)
Write `txt`, `json`, `jsonl`, or `csv`. With `-o`, the extension is used when `-of` is omitted (`.json`, `.jsonl`, `.csv`). With `-of` and no `-o`, that format is written to stdout instead of the text lines. JSON objects include status, size, time, word count, line count, payload, method, URL, final URL, and redirect count.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst -o hits.json
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst -of csv --silent > hits.csv
```

### 35. Auto-Calibration (-ac/--auto-calibrate)
Send one request with a random payload and hide later responses that have the same size, word count, and line count. This catches soft 404 pages that answer `200` with a fixed body.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst --auto-calibrate
```

### 36. Dry Run, Stdin, And Reproducible Order
`--dry-run` prints the requests and does not connect. `-w -` reads the wordlist from stdin. Lines that start with `#` are comments unless you pass `--keep-comments`. Duplicate payloads are removed unless you pass `--no-dedup`. `--seed` makes `--randomize` repeatable.
```bash
python3 skiff.py -u http://127.0.0.1/FUZZ -w wordlist.lst --dry-run --no-encode
printf 'admin\nsecret\n' | python3 skiff.py -u http://127.0.0.1/FUZZ -w - --silent
```

### 37. Version (-V/--version)
```bash
python3 skiff.py --version
```

## Output

Hits go to stdout. The banner, progress, warnings, and the final summary go to stderr, so a pipe can capture hits alone. `--silent` drops the banner, progress, and summary. Request errors are still reported, and a scan where every request failed exits with status 1.

A hit keeps the original three fields first, then adds timing and the payload:

```text
[Status: 200] [Size: 14] [URL: http://127.0.0.1/secret] [Time: 3ms] [Words: 2] [Lines: 1] [Payload: secret] [Method: GET]
```

Redirects add `[Redirects: N]` and `[Final: URL]` when the final URL differs. `Ctrl+C` stops the workers and exits with status 130.

----------------------------------------------------------------------------------------------------

## Installation
*NOTE* If you're using Kali Linux you may have to install on a python virtual environment. It's probably a good idea to do that anyways, but its optional.

### Setting up a python virtual environment
```bash
python3 -m venv /path/to/venv (ex: python3 -m venv /home/glask1d/myvenv)
```
#### Activate the environment
```bash
source /path/to/env/bin/activate
```

***(If you dont need a virtual environment you can skip the above steps)***

### Installing dependencies

```bash
pip3 install -r requirements.txt
```

***You should now be able to run the script***


## Notes

Skiff 2.0 renames the tool and changes the placeholder from `GOOB` to `FUZZ`. The flag for several placeholders is `--multi-fuzz`. These earlier fixes still hold:

- More threads than words could leave the scan waiting forever.
- Connection errors were discarded, including in verbose mode, and a bad command line still exited 0.
- `FUZZ` was replaced in every position at once, so `--multi-fuzz combo` did not build combinations. Request files now fuzz the request line, headers, and body, and a stale `Content-Length` is not sent.
- `--filter-code` did not trim spaces, `--filter-size 0` did nothing, and fractional `--rps` was treated as one request per second.
- `Ctrl+C` now stops the run instead of leaving the workers blocked.

Run the tests with:

```bash
python3 -m unittest tests.test_skiff
```

- Run into issues installing or running the tool?
- Found a bug?
- Have an idea for an additional feature?

Feel free to send me a DM on X(Twitter) or just tag me in a post. https://x.com/GLAsk1d

----------------------------------------------------------------------------------------------------


***Disclaimer: For Educational Purposes Only
Skiff is a web fuzzing tool developed for educational purposes and ethical security research. It is intended to assist security professionals and researchers in testing and improving the security of systems and applications with explicit permission from the system owner. 
Unauthorized use of Skiff to access, scan, or test systems without consent is strictly prohibited and may violate applicable laws. The developers and contributors of Skiff assume no liability for any misuse or damage caused by the tool. By using Skiff, you agree to use it responsibly, ethically, and in compliance with all relevant local, national, and international laws.***
