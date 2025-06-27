RedirectHunter
==============

RedirectHunter is a command-line tool for analyzing URL redirection chains. It follows HTTP redirects up to a configurable limit, detects redirect loops, logs transitions between domains, and inspects final landing pages for potential security issues such as HTML forms, meta-refresh tags, and JavaScript-based redirects.

Features:

- Manual tracking of up to N redirects (default: 10)
- Detection of redirect loops and missing Location headers
- Identification of cross-domain redirects
- Analysis of final landing pages for:
    - <form> elements
    - HTML meta refresh tags
    - JavaScript-based redirects using window.location
- Terminal output with color-coded logs
- Modular and extensible Go codebase

Use Cases:

- Bug bounty hunting
- Open redirect analysis
- Redirect behavior tracing in penetration tests
- Security assessment of final landing pages

Installation:

Clone the repository and build using Go:

git clone https://github.com/selimozcann/RedirectHunter.git
cd RedirectHunter
go build -o redirectHunter

Usage:

Prepare a text file containing URLs (e.g. `urls.txt`), one per line:

https://httpbin.org/redirect-to?url=https://example.com
https://httpbin.org/absolute-redirect/2

Run the tool:

go run main.go --file testdata/urls.txt

Or run the compiled binary:

./redirectHunter --file testdata/urls.txt

Sample Output:

[+] Scanning: https://httpbin.org/redirect-to?url=https://example.com
↪ https://httpbin.org/redirect-to?url=https://example.com → 302
↪ https://example.com → 200
↪ [DEBUG] Redirected to different domain: https://example.com
[!] <form> tag: https://example.com

Configuration:

The default maximum number of redirects is 10.
To change it, edit the `redirectAmount` variable in `scanner.go`:

redirectAmount := 100

## Project Structure:

📁 internal/analyzer → HTML analysis logic
📁 internal/output → Output formatting functions
📁 internal/scanner → Redirect tracing logic
📁 testdata/ → Example input files (e.g., urls.txt)
📄 main.go → Entry point

**Legal Notice**:

**This tool is intended for educational and authorized testing purposes only.
Do not scan domains you do not own or have explicit permission to test.**

