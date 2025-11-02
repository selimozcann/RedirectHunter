# RedirectHunter

RedirectHunter is a security-first URL tracing toolkit that maps every hop in a redirect chain and highlights abuse-ready behaviour along the way. It understands server responses, HTML meta refreshes, and client-side JavaScript redirects, then enriches each hop with detections such as SSRF, HTTPS downgrade, token leakage, and phishing indicators. Results can be streamed to JSONL and HTML simultaneously, making the tool equally useful in terminals and pipelines.

## Highlights

- **Deterministic reports** – JSONL and HTML outputs are written in a single pass so that automation can diff, archive, or re-use findings without post-processing.
- **First-class SSRF detection** – internal destinations are flagged both while tracing and after the final hop (via the `final-ssrf` plugin). The `postfuzz` helper now runs the same checks for body fuzzing workflows.
- **Client-side redirect discovery** – optional DOM inspection follows meta refreshes and JavaScript-driven relocations to surface deep chains.
- **Scalable scanning** – rate limiting, concurrency control, retries, and configurable headers/cookies make the CLI suitable for CI/CD and large target lists.
- **Plugin system** – drop-in evaluators can run after each trace. The built-in `final-ssrf` plugin is enabled by default; add your own by extending `internal/plugin`.

## Installation

RedirectHunter is a Go module. With Go 1.21+ installed:

```bash
go install github.com/selimozcann/RedirectHunter/cmd/redirecthunter@latest
go install github.com/selimozcann/RedirectHunter/cmd/postfuzz@latest
```

The binaries appear in `$(go env GOPATH)/bin`. You can also run either tool with `go run` during development.

## Usage

### Redirect chain discovery (`redirecthunter`)

```bash
go run ./cmd/redirecthunter \
  -u 'https://host/redirect-to?url=FUZZ' \
  -w wordlist.txt -t 20 -rl 5 -timeout 20s -retries 3 \
  -max-chain 15 -js-scan -cookie 'session=abc123' -insecure \
  -summary -plugins final-ssrf \
  -o ./examples/example.out.jsonl -html ./examples/example.report.html
```

What the command does:

1. Loads `wordlist.txt` and substitutes the single `FUZZ` token in `-u` for each payload.
2. Runs 20 workers with a 5 rps global rate limit, resilient retries, and relaxed TLS for lab work.
3. Enables JavaScript/meta redirect detection and the default `final-ssrf` plugin.
4. Streams JSONL and HTML reports while printing a concise console summary. Existing files are overwritten for deterministic CI artefacts.

### Body fuzzing with shared detections (`postfuzz`)

`postfuzz` drives single-request workflows (POST/PUT/GET) where the request body contains the fuzz point. Core SSRF detection now runs on every response and plugins execute just like the main CLI.

```bash
go run ./cmd/postfuzz \
  -u https://api.host.test/endpoint \
  -X POST \
  --body '{"url": "FUZZ"}' \
  --payloads ssrf_payloads.txt \
  --content-type application/json \
  -t 5 -rl 2 -retries 2 \
  -o out.jsonl -html report.html
```

Each payload expands `FUZZ` inside the JSON body, executes the request with retry/backoff logic, then emits findings. If the final URL resolves to an internal address the run is flagged as `SSRF` (core detection) and `FINAL_SSRF` (plugin). Console output mirrors the chain view and HTML/JSONL writers used by the main binary.

### Frequent flags

| Flag | Purpose |
| ---- | ------- |
| `-u` | Target URL. Both tools support a single `FUZZ` token for payload substitution. |
| `-w` | Wordlist for URL fuzzing. |
| `-payloads` | Wordlist for body fuzzing (falls back to `-w` when omitted). |
| `-t` | Concurrent workers (default `10`). |
| `-rl` | Global rate limit in requests/second (`0` disables limiting). |
| `-timeout` | Per-request timeout (default `8s`). |
| `-retries` | Automatic retry count (default `1`). |
| `-max-chain` | Maximum redirect hops (default `15`). |
| `-js-scan` | Toggle client-side redirect detection (enabled by default). |
| `-cookie` | Cookie header injected into every request. |
| `-H` | Extra HTTP headers (`-H 'Key: Value'`, repeatable). |
| `-proxy` | HTTP(S) proxy URL. |
| `-insecure` | Skip TLS verification (lab use only). |
| `-plugins` | Comma-separated plugin list (`final-ssrf` by default). |
| `-o` | JSONL output path. |
| `-html` | HTML report output path. |

## Findings and reports

A single JSONL line from `redirecthunter`:

```json
{"timestamp":"2024-04-01T12:00:00Z","input_url":"https://host/redirect-to?url=https://internal","payload":"https://internal","final_url":"https://internal","redirect_chain":["https://host/redirect-to?url=https://internal","https://internal"],"status_code":200,"resp_len":512,"duration_ms":142,"findings":[{"type":"HTTPS_DOWNGRADE","at_hop":1,"severity":"medium","detail":"https:// -> http://","source":"core"},{"type":"FINAL_SSRF","at_hop":1,"severity":"high","detail":"https://internal","source":"final-ssrf"}]}
```

The HTML report mirrors the same data: each section lists the redirect chain, followed by colour-coded findings with severity badges. Both output formats are deterministic to ease diffing and archival.

## Development

```bash
go test ./...
```

Pull requests and custom plugins are welcome. The codebase favours readability and standard library solutions so that extending detections or outputs stays straightforward.

## Legal notice

- Only scan targets for which you have explicit, written permission.
- Do not use this software to gain unauthorized access, disrupt services, or target regulated infrastructure (government, healthcare, finance) without consent.
- The authors disclaim all liability for misuse or damage resulting from unauthorized activities.
