# RedirectHunter

RedirectHunter is a security-focused command-line tool that discovers and traces full redirect chains. It follows server-side HTTP 3xx, HTML meta refreshes, and JavaScript redirects, then scores risky behaviour such as open redirects, token leakage, SSRF, or HTTPS downgrades.

## Features

- Severity scoring for findings (low/medium/high)
- Plugin system with a built-in final URL SSRF detector
- postfuzz mode for POST/PUT SSRF & Open Redirect fuzzing via body templates
- Configurable HTTP client with custom headers, cookies, proxies, retries
- HTML report with redirect chain visualization
- JSONL output format for downstream processing
- Response size (size) and duration (duration_ms) tracking
- Redirect loop and excessive chain detection
- Landing page phishing heuristics
- Output modes: default, --silent, --summary, and --only-risky
- Colourised terminal output aware of hop types
- Rate-limited parallel scanning (default 10 threads)

## Quick Start

Scan a single URL:

```bash
go run ./cmd/redirecthunter -u https://example.com
```

Fuzz a redirect parameter and generate reports

```bash
go run ./cmd/redirecthunter \
  -u 'https://host/redirect-to?url=FUZZ' \
  -w wordlist.txt -t 20 -rl 5 \
  -o out.jsonl -html report.html
```

Advanced redirect fuzzing
```bash
go run ./cmd/redirecthunter \
  -u 'https://host/redirect-to?url=FUZZ' \
  -w wordlist.txt -t 20 -rl 5 -timeout 20s -retries 3 \
  -max-chain 15 -js-scan -cookie 'session=abc123' -insecure \
  -summary -plugins final-ssrf \
  -o out.jsonl -html report.html
```

POST body fuzzing (postfuzz mode)
```bash
go run ./cmd/postfuzz/main.go \
  -u https://api.host.com/endpoint \
  -X POST \
  --body '{"url": "FUZZ"}' \
  --payloads payloads/ssrf.txt \
  --content-type application/json \
  -v
```


```bash
RedirectHunter (GET FUZZ)
-u Target URL (supports FUZZ)
-w Wordlist file (used when FUZZ is in URL)
-t Threads (default: 10)
-rl Global rate limit (requests per second)
-timeout Per-target timeout (default: 8s)
-retries Retry count (default: 1)
-max-chain Max redirect hops including JS/meta (default: 15)
-js-scan Enable JS/meta redirect detection (default: true)
-o JSONL output file
-html HTML report output file
-H Extra HTTP header (repeatable)
-cookie Cookie header
-proxy HTTP(S) proxy URL
-insecure Skip TLS verification
-silent Suppress chain output
-summary Show one-line summary per target
-only-risky Only output results with findings
-plugins Plugins to enable (default: final-ssrf)
```

```bash
PostFuzz (POST / PUT Body FUZZ)
-u Target URL
-X HTTP method (POST, PUT)
--body Request body template (use FUZZ as placeholder)
--payloads Wordlist file used to replace FUZZ
--content-type Content-Type header (default: application/json)
-v Verbose mode
```

Instance output.jsonl
```bash
{
  "target": "https://host.com",
  "chain": [
    {
      "index": 0,
      "url": "https://host.com",
      "method": "GET",
      "status": 302,
      "via": "http-location",
      "time_ms": 120,
      "final": false,
      "size": 420
    },
    {
      "index": 1,
      "url": "https://target.com",
      "method": "GET",
      "status": 200,
      "via": "http-location",
      "time_ms": 700,
      "final": true,
      "size": 648
    }
  ],
  "findings": [
    {
      "type": "HTTPS_DOWNGRADE",
      "at_hop": 1,
      "severity": "medium",
      "detail": "https:// -> http://"
    }
  ],
  "started_at": "2025-09-08T19:15:22Z",
  "duration_ms": 832
}

```
## Legal Disclaimer
- You have explicit written permission to test any target system.
- You will not use this software for any unauthorized access, scanning, or disruption of services.
- Usage against government, financial, or healthcare infrastructure without authorization is strictly prohibited.
- The developer disclaims all liability for misuse or damage caused by unauthorized use.


