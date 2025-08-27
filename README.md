# RedirectHunter v3

RedirectHunter is a security-focused CLI that discovers and traces full redirect chains. It follows HTTP 3xx, JavaScript and HTML meta refreshes, then scores any risky behavior such as open redirects, token leakage, SSRF or HTTPS downgrades.

## Features
- Risk scoring on findings (low/medium/high)
- Plugin system with built-in final URL SSRF detector
- HTML report with redirect chain visualisation
- Custom header injection and cookie support
- Redirect loop and excessive chain detection
- Landing page phishing heuristics
- `--silent`, `--summary` and `--only-risky` output modes
- Colourised terminal output aware of hop types
- Rate limited parallel scanning (default 10 threads)
- JSONL output format for downstream processing

## Quick start
Scan a single URL:
```bash
go run ./cmd/redirecthunter -u https://example.com
```

Fuzz a parameter and write JSONL and HTML reports:
```bash
go run ./cmd/redirecthunter \
  -u https://host/redirect?to=FUZZ \
  -w words.txt -t 20 -rl 5 \
  -o out.jsonl -html report.html
```

## Flags
| Flag | Description |
|------|-------------|
| `-u` | Single URL (supports `FUZZ` placeholder) |
| `-w` | Wordlist when `-u` contains `FUZZ`; stdin if omitted |
| `-t` | Threads (default 10) |
| `-rl` | Global rate limit req/sec (0 = unlimited) |
| `-timeout` | Per-target timeout (default 8s) |
| `-retries` | Retry count for transient errors (default 1) |
| `-max-chain` | Max hops including meta/JS (default 15) |
| `-js-scan` | Enable HTML/JS redirect detection (default true) |
| `-o` | JSONL output file |
| `-html` | HTML report output file |
| `-H` | Extra HTTP header (repeatable) |
| `-cookie` | Cookie header |
| `-proxy` | HTTP(S) proxy URL |
| `-insecure` | Skip TLS verification |
| `-silent` | Suppress detailed chain output |
| `-summary` | Print one-line summary per target |
| `-only-risky` | Output only results with findings |
| `-plugins` | Comma-separated plugins to enable (default `final-ssrf`) |

## JSONL schema
Each line in the output represents a `Result` object:
```json
{
  "target": "https://example.com",
  "chain": [
    {"index":0,"url":"https://example.com","status":302,"via":"http-location","time_ms":12},
    {"index":1,"url":"https://other","status":200,"via":"http-location","time_ms":20,"final":true}
  ],
  "findings": [
    {"type":"HTTPS_DOWNGRADE","at_hop":1,"severity":"medium","detail":"https://a -> http://b"}
  ],
  "started_at": "2024-01-01T00:00:00Z",
  "duration_ms": 42
}
```

## Development
```bash
go vet ./...
golangci-lint run ./...
go test ./...
```

RedirectHunter targets Go 1.24.4 and relies only on the standard library.

## Legal Disclaimer
This tool is intended for educational and authorised security testing only. Use it strictly within legal boundaries and only on systems you have explicit permission to test.
