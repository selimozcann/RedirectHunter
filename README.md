# redirecthunter

redirecthunter traces full HTTP redirect chains and flags risky behavior like SSRF targets, HTTPS downgrades and token leakage.
It supports parallel scanning, optional HTML/JavaScript redirect detection and JSONL output for downstream processing.

## Usage

### Quick Start

Single URL status viewer:

```bash
cd RedirectHunter
go run . https://example.com
```

Full redirect scanner:

```bash
cd RedirectHunter
go run ./cmd/redirecthunter \
    -u https://host/redirect?to=FUZZ \
    -w words.txt -t 20 -rl 5 -js-scan -o out.jsonl
```

The output color-codes HTTP statuses: 2xx responses (e.g., 200) appear green, 3xx such as 302 appear blue, and 4xx like 400 appear red.

### Flags

| Flag | Description |
| ---- | ----------- |
| `-u` | Single URL (supports `FUZZ` placeholder) |
| `-w` | Wordlist file (used when `-u` contains `FUZZ`; stdin used if omitted) |
| `-t` | Threads (default 10) |
| `-rl` | Global rate limit req/sec (default 0 = unlimited) |
| `-timeout` | Per-target timeout (default 8s) |
| `-retries` | Retry count for transient errors (default 1) |
| `-max-chain` | Max hops including meta/JS (default 15) |
| `-mc` | Match status classes/codes (e.g. `30x,200,404`) |
| `-js-scan` | Enable HTML/JS redirect detection |
| `-o` | Output file (default stdout) |
| `-of` | Output format: `jsonl` (default) |
| `-H` | Extra HTTP header (repeatable) |
| `-cookie` | Cookie header |
| `-proxy` | HTTP(S) proxy URL |
| `-insecure` | Skip TLS verification |

## JSONL Schema

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

```
go vet ./...
golangci-lint run ./...
go test ./...
```

The project targets Go 1.24.4 and relies only on the standard library.

## Legal Disclaimer

This tool is intended for educational and authorized security testing only.
Use it strictly within legal boundaries and only on systems you have explicit permission to test.

