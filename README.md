# RedirectHunter

RedirectHunter is a security-focused command-line tool that discovers and traces full redirect chains. It follows server-side HTTP 3xx, HTML meta refreshes, and JavaScript redirects, then scores risky behaviour such as open redirects, token leakage, SSRF, or HTTPS downgrades.

## Features

- Deterministic dual-report output: JSONL and HTML can be generated at the same time.
- Built-in summary dashboard with client-side filtering in the HTML report.
- Severity scoring for findings (low/medium/high) and plugin-sourced insights.
- Plugin system with a built-in final URL SSRF detector.
- Configurable HTTP client with custom headers, cookies, proxies, retries, and TLS controls.
- Response size, duration, loop detection, phishing heuristics, and JS/meta redirect tracing.
- Output modes: default, `--silent`, `--summary`, and `--only-risky` for console output control.
- Rate-limited parallel scanning (default 10 threads) suitable for CI/CD pipelines.

## Quick Start

The canonical run below exercises fuzzing, plugin loading, JSONL output, and the HTML report in one command. Copy/paste the snippet as-is; it writes sample artefacts to `./examples/` which are also committed to the repository for reference.

```bash
go run ./cmd/redirecthunter \
  -u 'https://host/redirect-to?url=FUZZ' \
  -w wordlist.txt -t 20 -rl 5 -timeout 20s -retries 3 \
  -max-chain 15 -js-scan -cookie 'session=abc123' -insecure \
  -summary -plugins final-ssrf \
  -o ./examples/example.out.jsonl -html ./examples/example.report.html
```

Key behaviours demonstrated by the command:

- Loads `wordlist.txt` and replaces the single `FUZZ` token in the URL for each payload.
- Runs 20 concurrent workers with a rate limit of 5 requests/second and resilient HTTP retries.
- Enables JavaScript/meta redirect detection, insecure TLS for lab testing, and the `final-ssrf` plugin.
- Emits deterministic JSONL and HTML reports (overwriting if the files already exist) while printing a concise console summary.

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


## Common Flags

| Flag | Description |
| ---- | ----------- |
| `-u` | Target URL (supports a single `FUZZ` token for fuzzing). |
| `-w` | Wordlist file used to expand `FUZZ` into concrete payloads. |
| `-t` | Number of concurrent workers (default `10`). |
| `-rl` | Rate limit in requests/second; `0` disables throttling. |
| `-timeout` | Per-request timeout (default `8s`). |
| `-retries` | Automatic HTTP retry count (default `1`). |
| `-max-chain` | Maximum hops (server or client side) followed per target (default `15`). |
| `-js-scan` | Enable client-side redirect detection (`true` by default). |
| `-cookie` | Cookie header injected into every request. |
| `-H` | Extra HTTP headers (`-H 'Key: Value'`, repeatable). |
| `-proxy` | HTTP(S) proxy URL. |
| `-insecure` | Skip TLS certificate verification (lab use only). |
| `-summary` | Print one-line summaries instead of full chains. |
| `-silent` | Suppress console output (still writes files). |
| `-only-risky` | Print only targets with findings or errors. |
| `-plugins` | Comma-separated plugin list (default `final-ssrf`). |
| `-o` | JSONL output path; overwritten if it exists. |
| `-html` | HTML report output path; overwritten if it exists. |

Instance output.jsonl
```bash
{"timestamp":"2024-04-01T12:00:00Z","input_url":"https://host/redirect-to?url=https://internal","payload":"https://internal","final_url":"https://internal","redirect_chain":["https://host/redirect-to?url=https://internal","https://internal"],"status_code":200,"resp_len":512,"duration_ms":142,"findings":[{"type":"HTTPS_DOWNGRADE","at_hop":1,"severity":"medium","detail":"https:// -> http://","source":"core"}],"plugin_findings":[{"type":"FINAL_SSRF","at_hop":1,"severity":"high","detail":"https://internal","source":"final-ssrf"}]}
```
## Legal Disclaimer
- You have explicit written permission to test any target system.
- You will not use this software for any unauthorized access, scanning, or disruption of services.
- Usage against government, financial, or healthcare infrastructure without authorization is strictly prohibited.
- The developer disclaims all liability for misuse or damage caused by unauthorized use.


