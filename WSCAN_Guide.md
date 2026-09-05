# WSCAN — Web Weakness Scanner

**Built by NEXO-TECH**  •  **Running on ASTERISK OS**  •  Version 1.0

A learning-grade web vulnerability scanner written in Python. It crawls a
site, checks security posture, and runs active tests for common weaknesses.

---

## 1. What It Detects

| Category | Checks |
|---|---|
| Headers | Missing CSP, X-Frame-Options, HSTS, X-Content-Type-Options, etc. |
| Cookies | Missing `Secure` / `HttpOnly` flags |
| SQL Injection | Error-based and time-based (blind) |
| Reflected XSS | Payload reflection in responses |
| Command Injection | Command output echoed back |
| Open Redirect | External redirect via URL parameters |
| Sensitive Files | `.env`, `.git`, backups, config leaks |

**Severity scale:** `critical` → `high` → `medium` → `low`

---

## 2. Requirements

- Python 3.6+
- The `requests` library  (`pip install requests`)

---

## 3. Setup

```bash
# 1. Make the shell tool executable
chmod +x run.sh

# 2. Run it — it auto-installs 'requests' if missing
./run.sh
```

---

## 4. Usage

### Interactive mode (recommended for learning)
```bash
./run.sh
```
The tool will ask you for:
1. **Target URL** — e.g. `http://localhost:3000`
2. **Max URLs** to crawl (default 30)
3. **Delay** between requests in seconds (default 0.3)
4. **Which tests** to run — `all`, or a list like `sql,xss`
5. **Cookie flag checks?** (y/N)
6. **Sensitive file probing?** (y/N)

### Command-line mode (for automation)
```bash
./run.sh https://example.com
./run.sh https://example.com --sensitive --cookies
./run.sh https://example.com --method sql --max-urls 10
```

### Options reference
| Option | Description |
|---|---|
| `--max-urls N` | Stop after crawling N pages |
| `--delay S` | Seconds between requests (be polite) |
| `--method sql,xss,cmdi,redir` | Only run chosen active tests |
| `--cookies` | Flag weak cookie flags |
| `--sensitive` | Probe for exposed sensitive files |
| `--no-verify` | Skip TLS cert verification (self-signed labs) |
| `--json-out FILE` | Write a JSON report |

---

## 5. Recommended Practice Labs

Only scan systems you own or have written permission to test.

- **OWASP Juice Shop**
  ```bash
  docker run -d -p 3000:3000 bkimminich/juice-shop
  # then scan:  ./run.sh http://localhost:3000
  ```
- **DVWA**
  ```bash
  docker run -d -p 80:80 vulnerables/web-dvwa
  ```
- **Mutillidae / bWAPP** — deliberately vulnerable labs

---

## 6. Understanding Results

- Findings are printed sorted by severity (highest first).
- Each shows: severity, type, URL/method, and a **proof** string.
- **Always verify findings manually** — regex/timing checks can produce
  false positives. Confirm with Burp Suite or a manual request before
  trusting a result.

---

## 7. Limitations

- Tests query-string parameters only (no POST/JSON bodies yet).
- No authentication support — can't scan behind a login wall.
- No stealth; basic payloads; WAFs will often block it.
- Regex + timing detection → expect false positives.

---

## 8. Legal / Ethical Note

This tool is for **authorized** security testing and education only.
Only scan targets you own or are explicitly permitted to test. Unauthorized
scanning may be illegal.
