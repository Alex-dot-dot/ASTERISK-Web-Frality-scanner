#!/usr/bin/env python3
"""
wscan.py - Interactive web weakness scanner
Usage:
    python3 wscan.py                # interactive: it asks for target + options
    python3 wscan.py URL [options]  # or full CLI mode for automation
Detects: missing security headers, exposed sensitive files, SQLi,
reflected XSS, command injection, open redirect, weak cookies.
Built by NEXO-TECH  •  Running on ASTERISK OS
"""
import argparse
import json
import re
import sys
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qs

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit("pip install requests  (required dependency)")


# ------------------------------------------------------------ big ASCII banner
def banner():
    print("""
██████╗ ██╗   ██╗██╗██╗  ████████╗    ██████╗ ██╗   ██╗
██╔══██╗██║   ██║██║██║  ╚══██╔══╝    ██╔══██╗██║   ██║
██████╔╝██║   ██║██║██║     ██║       ██████╔╝██║   ██║
██╔══██╗██║   ██║██║██║     ██║       ██╔═══╝ ██║   ██║
██████╔╝╚██████╔╝██║███████╗██║       ██║     ╚██████╔╝
╚═════╝  ╚═════╝ ╚═╝╚══════╝╚═╝       ╚═╝      ╚═════╝

███╗   ██╗███████╗██╗  ██╗ ██████╗    ████████╗███████╗ ██████╗██╗  ██╗
████╗  ██║██╔════╝╚██╗██╔╝██╔═══██╗   ╚══██╔══╝██╔════╝██╔════╝██║  ██║
██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║      ██║   █████╗  ██║     ███████║
██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║      ██║   ██╔══╝  ██║     ██╔══██║
██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝      ██║   ███████╗╚██████╗██║  ██║
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝       ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝

█████╗ ███████╗████████╗███████╗██████╗ ██╗███████╗██╗   ██╗    ██████╗ █�[...]
██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗██║██╔════╝╚██╗ ██╔╝    ██╔══[...]
███████║███████╗   ██║   █████╗  ██████╔╝██║███████╗ ╚████╔╝     ██████╔╝███[...]
██╔══██║╚════██║   ██║   ██╔══╝  ██╔══██╗██║╚════██║  ╚██╔╝      ██╔══██╗╚═══�[...]
██║  ██║███████║   ██║   ███████╗██║  ██║██║███████║   ██║       ██████╔╝███████[...]
╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝   ╚═╝       ╚═════╝ ╚══════��[...]
""")


# ---------------------------------------------------------------- findings store
class Finding:
    def __init__(self, url, title, severity, detail="", method="GET", proof=""):
        self.url, self.title = url, title
        self.severity = severity
        self.detail = detail
        self.method = method
        self.proof = proof

    def to_dict(self):
        return vars(self)


# ------------------------------------------------- HTML link/input extractor
class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []          # [(action, method, [(name, type)])]
        self._cur_form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._cur_form = [a.get("action", ""),
                              (a.get("method") or "get").lower(), []]
            self.forms.append(self._cur_form)
        elif tag == "input" and self._cur_form:
            self._cur_form[2].append((a.get("name"), a.get("type", "text")))


# ---------------------------------------------------------------- payload sets
SQLI_ERR = ("SQL injection (error-based)", "high",
            ["'", '"', "1' OR '1'='1", '1" OR "1"="1", "1' AND '1'='1"])
SQLI_TIME = ("SQL injection (time-based/blind)", "high",
             ["1' AND SLEEP(4)-- -", "1 OR SLEEP(4)", "1;WAITFOR DELAY '0:0:4'--"])
XSS = ("Reflected XSS", "medium",
       ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", '\"<svg/onload=alert(1)>'])
CMDI = ("Command injection", "critical",
        [";id", "|id", "`id`", "$(id)", ";ping -c 3 127.0.0.1"])
REDIR = ("Open redirect", "medium",
         ["//evil.com", "https://evil.com", "/\\evil.com"])

SENSITIVE_FILES = [
    ".git/config", ".git/HEAD", ".env", ".env.bak", "backup.zip",
    "backup.sql", "db.sqlite3", ".DS_Store", "wp-config.php.bak",
    "config.php.bak", "phpinfo.php", ".htaccess",
]


# ---------------------------------------------------------------- scanner core
class WScan:
    def __init__(self, base, args):
        self.base = (base or "").rstrip("/")
        self.args = args
        self.session = requests.Session()
        self.session.verify = not getattr(args, "no_verify", False)
        self.seen, self.queue = set(), [base]
        self.findings = []
        self.urls_scanned = 0

    def request(self, url, method="GET", params=None, data=None, timeout=12):
        try:
            return self.session.request(
                method, url, params=params, data=data, timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "wscan/1.0 (NEXO-TECH ASTERISK OS)"})
        except requests.RequestException:
            return None

    def add(self, url, title, sev, detail="", method="GET", proof=""):
        self.findings.append(Finding(url, title, sev, detail, method, proof))

    # ---- passive checks
    def check_headers(self, r, url):
        for h in ["Content-Security-Policy", "X-Frame-Options",
                  "X-Content-Type-Options", "Strict-Transport-Security",
                  "Referrer-Policy", "Permissions-Policy"]:
            if h not in r.headers:
                self.add(url, f"Missing security header: {h}", "low",
                         "Improves XSS/clickjacking/leakage posture.")
        srv = r.headers.get("Server", "")
        if re.search(r"Apache/2\.[0-2]\.|nginx/1\.[0-8]\.|IIS/[0-6]\.", srv):
            self.add(url, f"Potentially outdated server: {srv}", "medium")

    def check_cookies(self, r, url):
        for c in self.session.cookies:
            flags = []
            if not c.secure:
                flags.append("missing Secure")
            if not hasattr(c, "_rest") or "httponly" not in c._rest:
                flags.append("missing HttpOnly")
            if flags and getattr(self.args, "cookies", False):
                self.add(url, f"Weak cookie '{c.name}'", "medium", "; ".join(flags))

    def check_security_file(self, url):
        r = self.request(url)
        if not r or r.status_code != 200:
            return False
        low = r.text[:4000].lower()
        path = urlparse(url).path.split("?")[0]
        checks = {
            ".git/config": "[core]" in low or "repositoryformatversion" in low,
            ".git/head": "ref:" in low,
            ".env": bool(re.search(r"(secret|api_key|password|token)\s*=", low)),
        }
        return bool(checks.get(path, True))

    # ---- active tests on a single parameter
    def test_param(self, url, param, value):
        tests = [("sql", SQLI_ERR), ("sql", SQLI_TIME),
                 ("xss", XSS), ("cmdi", CMDI), ("redir", REDIR)]
        methods = getattr(self.args, "method", None)
        for label, (title, sev, payloads) in tests:
            if methods and "sql" not in methods and label in ("sql",):
                continue
            if methods and label != "sql" and label not in methods:
                continue
            for payload in payloads:
                before = time.time()
                r = self.request(url, params={param: payload})
                if not r:
                    continue
                elapsed = time.time() - before
                body = r.text
                hit = None
                if label == "sql":
                    if re.search(r"SQL syntax|mysql_fetch|ORA-\d|Unclosed quotation|"
                                 r"PostgreSQL.*ERROR|Microsoft OLE DB|near \"", body, re.I):
                        hit = "DB error reflected"
                    elif elapsed >= 3.5:
                        hit = f"delayed {elapsed:.1f}s (blind)"
                elif label == "xss":
                    if payload in body or "alert(1)" in body:
                        hit = "payload reflected"
                elif label == "cmdi":
                    if re.search(r"uid=\d|root:x:|GID=\d", body):
                        hit = "command output reflected"
                elif label == "redir":
                    if "evil.com" in r.url and \
                            urlparse(r.url).netloc != urlparse(self.base).netloc:
                        hit = "redirected to external host"
                if hit:
                    self.add(url, title, sev,
                             f"param '{param}' :: {payload} -> {hit}", proof=payload)
                time.sleep(getattr(self.args, "delay", 0.3))

    # ---- crawl one page
    def process_page(self, url):
        self.urls_scanned += 1
        r = self.request(url)
        if not r:
            return
        self.check_headers(r, url)
        self.check_cookies(r, url)
        if r.status_code >= 500:
            self.add(url, f"Server error {r.status_code}", "medium",
                     "May expose stack traces / DoS-prone.")
        if "text/html" not in (r.headers.get("Content-Type") or ""):
            return

        # query-string params
        for k in parse_qs(urlparse(r.url).query):
            self.test_param(url, k, "1")

        p = PageParser()
        try:
            p.feed(r.text)
        except Exception:
            return
        # enqueue same-origin links
        for lnk in p.links:
            nxt = urljoin(url, lnk)
            if self.same_origin(nxt) and nxt not in self.seen and \
                    len(self.seen) < self.args.max_urls:
                self.seen.add(nxt)
                self.queue.append(nxt)

    def same_origin(self, u):
        p = urlparse(u)
        return p.netloc == urlparse(self.base).netloc and \
            p.scheme in ("http", "https")

    def run(self):
        self.seen.add(self.base)
        while self.queue and self.urls_scanned < self.args.max_urls:
            self.process_page(self.queue.pop(0))
            time.sleep(self.args.delay)

        if getattr(self.args, "sensitive", False):
            for f in SENSITIVE_FILES:
                target = urljoin(self.base + "/", f)
                if self.check_security_file(target):
                    self.add(target, f"Sensitive file exposed: {f}", "high")
        return self.report()

    def report(self):
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        out = sorted(self.findings, key=lambda x: order.get(x.severity, 9))
        print("\n" + "=" * 70)
        print(f"WSCAN REPORT  target={self.base}  urls={self.urls_scanned} "
              f"findings={len(out)}")
        print("=" * 70)
        for f in out:
            print(f"[{f.severity.upper():8}] {f.title}")
            print(f"         {f.method} {f.url}")
            if f.proof:
                print(f"         proof: {f.proof}")
        return [f.to_dict() for f in out]


# ---------------------------------------------------------------- interactive setup
def interactive_setup():
    print("\n" + "=" * 60)
    print("          SCAN CONFIGURATION  (press Enter for default)")
    print("=" * 60)
    url = input("[?] Target URL (e.g. http://localhost:8080): ").strip()
    while not url:
        url = input("[!] URL is required: ").strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        mx = int(input("[?] Max URLs to crawl   [30] : ").strip() or 30)
    except ValueError:
        mx = 30
    try:
        delay = float(input("[?] Delay between reqs (s) [0.3]: ").strip() or 0.3)
    except ValueError:
        delay = 0.3

    print("\n[?] Tests (comma-sep): sql,xss,cmdi,redir  or 'all'")
    raw = input("    all = everything  [all]: ").strip().lower()
    if raw in ("", "all"):
        methods = None
    else:
        methods = [m.strip() for m in raw.split(",") if m.strip()]

    cook = input("[?] Check cookie flags? (y/N): ").strip().lower() == "y"
    sens = input("[?] Probe sensitive files? (y/N): ").strip().lower() == "y"

    data = {"url": url, "max_urls": mx, "delay": delay, "method": methods,
            "cookies": cook, "sensitive": sens, "no_verify": False,
            "verbose": False, "json_out": None}
    return type("NS", (), data)()


# ---------------------------------------------------------------- CLI / entry
def build_argparser():
    ap = argparse.ArgumentParser(description="Web weakness scanner")
    ap.add_argument("url", nargs="?")
    ap.add_argument("--max-urls", type=int, default=30)
    ap.add_argument("--delay", type=float, default=0.3)
    ap.add_argument("--method", nargs="+", choices=["sql", "xss", "cmdi", "redir"])
    ap.add_argument("--cookies", action="store_true")
    ap.add_argument("--sensitive", action="store_true")
    ap.add_argument("--no-verify", action="store_true")
    ap.add_argument("--json-out")
    ap.add_argument("--verbose", action="store_true")
    return ap


def main():
    banner()
    ap = build_argparser()
    args = ap.parse_args()

    if not args.url:
        # interactive: no target given on command line
        ns_data = interactive_setup()
        for k, v in vars(ns_data).items():
            setattr(args, k, v)

    print("\n[+] Target      :", args.url)
    print("[+] Max URLs    :", args.max_urls)
    print("[+] Active tests:", ",".join(args.method) if args.method else "all")
    print("-" * 60)

    s = WScan(args.url, args)
    results = s.run()
    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\nJSON report written to {args.json_out}")


if __name__ == "__main__":
    main()
