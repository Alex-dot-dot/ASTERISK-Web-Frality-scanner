#!/usr/bin/env python3
"""
defender.py - Defender orchestrator for web weakness detection

Drop this file into the repository root next to wscan.py / recursive-web_scan.py.

Purpose:
- Provide the Defender class which orchestrates passive and optional active scans,
  applies a rule-driven scoring engine, deduplicates/normalizes findings, and exports
  results in multiple formats (terminal, JSON, SARIF).
- Modular design: add rules via Defender.register_rule(fn) where each fn inspects
  a response or URL and yields 0+ Finding objects.

Safety:
- Conservative by default: aggressive actions (form submission, intrusive payloads)
  require --aggressive to be set.
"""

from __future__ import annotations
import argparse
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, asdict
from typing import Callable, Iterable, List, Dict, Any
from urllib.parse import urljoin

# Try to reuse existing scanner code if present; fall back to minimal inspector
try:
    # The recursive inspector filename may be recursive-web_scan.py; import style fallback:
    from recursive_web_scan import RecursiveInspector, Finding as InspectorFinding  # type: ignore
except Exception:
    try:
        from recursive-web_scan import RecursiveInspector, Finding as InspectorFinding  # type: ignore  # noqa: F401
    except Exception:
        RecursiveInspector = None
        InspectorFinding = None  # type: ignore

# Lightweight Finding dataclass for Defender-level aggregation
@dataclass
class Finding:
    url: str
    title: str
    severity: str = "info"  # critical, high, medium, low, info
    detail: str = ""
    source: str = ""  # which engine produced this
    proof: str = ""
    score: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

# Severity to numeric priority mapping (lower is worse)
SEVERITY_WEIGHT = {"critical": 100, "high": 70, "medium": 40, "low": 10, "info": 1}

class Defender:
    def __init__(self, base_url: str, args):
        self.base = (base_url or "").rstrip("/")
        self.args = args
        self.rules: List[Callable[[str, Any], Iterable[Finding]]] = []
        self.findings: List[Finding] = []
        self.logger = logging.getLogger("defender")
        if args.verbose:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

    # --- Rule management ---
    def register_rule(self, fn: Callable[[str, Any], Iterable[Finding]]):
        """Register a rule function that takes (url, response_or_meta) and yields Finding."""
        self.rules.append(fn)

    # --- Core orchestration ---
    def run_passive(self):
        """Run passive crawl/inspection using RecursiveInspector if available,
           otherwise abort with a helpful message."""
        if RecursiveInspector is None:
            self.logger.error("RecursiveInspector not available. Add recursive-web_scan.py or run wscan.py.")
            raise RuntimeError("No inspector available")
        self.logger.info("Starting passive inspection using RecursiveInspector")
        insp = RecursiveInspector(self.base, self.args)
        report = insp.run()  # report is list of inspector dicts or InspectorFinding objects
        # Normalize inspector findings into our Finding type
        for item in report:
            # item may be dict or InspectorFinding-like
            if isinstance(item, dict):
                f = Finding(url=item.get("url", self.base),
                            title=item.get("title", ""),
                            severity=item.get("severity", "info"),
                            detail=item.get("detail", ""),
                            source="passive")
            else:
                # best-effort mapping
                f = Finding(url=getattr(item, "url", self.base),
                            title=getattr(item, "title", ""),
                            severity=getattr(item, "severity", "info"),
                            detail=getattr(item, "detail", ""),
                            source="passive")
            f.score = SEVERITY_WEIGHT.get(f.severity, 0)
            self.findings.append(f)

    def run_active(self):
        """Active tests: uses wscan-like active tests (SQLi/XSS/etc.) only when --aggressive is set.
           Placeholder - small integration for active tests can be added here."""
        if not getattr(self.args, "aggressive", False):
            self.logger.info("Active tests are disabled (use --aggressive to enable).")
            return
        # Attempt to import WScan from wscan.py
        try:
            from wscan import WScan  # type: ignore
        except Exception as e:
            self.logger.error("Active tests require wscan.py with WScan class available: %s", e)
            return
        self.logger.info("Starting active tests using WScan (aggressive mode)")
        ws = WScan(self.base, self.args)
        results = ws.run()  # returns list of dicts (findings)
        for r in results:
            f = Finding(url=r.get("url", self.base),
                        title=r.get("title", ""),
                        severity=r.get("severity", "info"),
                        detail=r.get("detail", ""),
                        source="active",
                        proof=r.get("proof", ""))
            f.score = SEVERITY_WEIGHT.get(f.severity, 0)
            self.findings.append(f)

    # --- Rule engine for additional checks
    def apply_rules(self, url: str, meta: Any):
        """Apply registered rules to a response or meta dict (for each URL)."""
        for rule in self.rules:
            try:
                for found in rule(url, meta):
                    if isinstance(found, Finding):
                        found.score = SEVERITY_WEIGHT.get(found.severity, 0)
                        self.findings.append(found)
                    else:
                        # convert simple dict-like result
                        self.findings.append(Finding(**found))
            except Exception as e:
                self.logger.exception("Rule %s failed for %s: %s", rule.__name__, url, e)

    # --- Dedupe & scoring
    def dedupe_and_score(self):
        """Normalize and deduplicate findings by (url,title,proof); pick highest severity."""
        keymap: Dict[tuple, Finding] = {}
        for f in self.findings:
            key = (f.url, f.title, f.proof or "")
            existing = keymap.get(key)
            if not existing:
                keymap[key] = f
            else:
                # keep the higher severity / score / longer detail
                if f.score > existing.score:
                    keymap[key] = f
                elif f.score == existing.score and len(f.detail or "") > len(existing.detail or ""):
                    keymap[key] = f
        self.findings = sorted(keymap.values(), key=lambda x: x.score, reverse=True)

    # --- Reporters
    def report_terminal(self):
        print("\n" + "=" * 70)
        print(f"DEFENDER REPORT  target={self.base}  findings={len(self.findings)}")
        print("=" * 70)
        for f in self.findings:
            print(f"[{f.severity.upper():8}] {f.title}")
            print(f"         {f.url}")
            if f.proof:
                print(f"         proof: {f.proof}")
            if f.detail:
                print(f"         detail: {f.detail}")

    def report_json(self, path: str):
        objects = [f.to_dict() for f in self.findings]
        with open(path, "w") as fh:
            json.dump(objects, fh, indent=2)
        self.logger.info("JSON report written to %s", path)

    def report_sarif(self, path: str):
        """Emit a simple SARIF-like report (note: minimal fields, not a full SARIF implementation)."""
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Defender", "informationUri": "https://github.com/Alex-dot-dot/ASTERISK-Web-Frality-scanner"}},
                "results": []
            }]
        }
        for f in self.findings:
            sarif["runs"][0]["results"].append({
                "ruleId": f.title,
                "level": f.severity,
                "message": {"text": f.detail or f.proof or ""},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.url}}}]
            })
        with open(path, "w") as fh:
            json.dump(sarif, fh, indent=2)
        self.logger.info("SARIF report written to %s", path)

    # --- High-level flow
    def run(self):
        start = time.time()
        # 1) Passive inspection
        try:
            self.run_passive()
        except Exception as e:
            self.logger.error("Passive run failed: %s", e)

        # 2) Apply custom rule engine to passive results if any rule wants meta input
        for f in list(self.findings):
            meta = {"title": f.title, "detail": f.detail}
            self.apply_rules(f.url, meta)

        # 3) Optional active tests
        try:
            self.run_active()
        except Exception as e:
            self.logger.error("Active run failed: %s", e)

        # 4) Dedupe & scoring
        self.dedupe_and_score()

        elapsed = time.time() - start
        self.logger.info("Defender finished in %.1fs — findings=%d", elapsed, len(self.findings))
        return self.findings

# --- Some example built-in rules (you can add more or plugins) ---

def rule_open_redirect_param(url: str, meta: Any):
    u = url.lower()
    if "redirect=" in u or "next=" in u or "url=" in u:
        yield Finding(url=url, title="Possible open-redirect parameter", severity="medium", detail="URL contains redirect-like parameter", source="rule_open_redirect_param")

def rule_webshell_signature(url: str, meta: Any):
    d = (meta.get("detail") or "").lower() if isinstance(meta, dict) else ""
    signatures = ["eval(base64_decode", "shell_exec(", "preg_replace("]
    for s in signatures:
        if s in d:
            yield Finding(url=url, title="Suspicious webshell signature", severity="critical", detail=f"signature: {s}", source="rule_webshell_signature")

# --- CLI wrapper ---
def build_argparser():
    ap = argparse.ArgumentParser(description="Defender orchestrator for web weakness detection")
    ap.add_argument("url", help="Target URL (e.g., https://example.com)")
    ap.add_argument("--json-out", help="Write findings JSON to file")
    ap.add_argument("--sarif-out", help="Write a SARIF-like file")
    ap.add_argument("--aggressive", action="store_true", help="Enable active/intrusive tests (use responsibly)")
    ap.add_argument("--workers", type=int, default=1, help="Worker count for passive inspector (if supported)")
    ap.add_argument("--max-urls", type=int, default=200, help="Max URLs to traverse")
    ap.add_argument("--delay", type=float, default=0.2, help="Delay between requests (s)")
    ap.add_argument("--cookies", action="store_true", help="Enable cookie checks")
    ap.add_argument("--sensitive", action="store_true", help="Probe for sensitive files")
    ap.add_argument("--no-verify", action="store_true", help="Do not verify TLS certificates")
    ap.add_argument("--respect-robots", action="store_true", help="Respect robots.txt")
    ap.add_argument("--verbose", action="store_true", help="Verbose logging")
    return ap

def main():
    ap = build_argparser()
    args = ap.parse_args()
    url = args.url
    if not url.startswith(("http://","https://")):
        url = "http://" + url

    # adapt args to pass to RecursiveInspector/WScan if present
    class DummyArgs: pass
    darr = DummyArgs()
    darr.max_urls = args.max_urls
    darr.delay = args.delay
    darr.cookies = args.cookies
    darr.sensitive = args.sensitive
    darr.no_verify = args.no_verify
    darr.respect_robots = args.respect_robots
    darr.verbose = args.verbose
    darr.aggressive = args.aggressive
    darr.workers = args.workers

    d = Defender(url, darr)

    # register example rules (you can register additional functions at runtime)
    d.register_rule(rule_open_redirect_param)
    d.register_rule(rule_webshell_signature)

    findings = d.run()
    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump([f.to_dict() for f in findings], fh, indent=2)
        print(f"[+] JSON written to {args.json_out}")
    else:
        d.report_terminal()

    if args.sarif_out:
        d.report_sarif(args.sarif_out)

if __name__ == "__main__":
    main()
