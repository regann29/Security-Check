#!/usr/bin/env python
"""Phase 1-2 health check for Security Health Check.

Run from the project root:
    python scripts/verify_phase12.py                  # live test uses gmail.com
    python scripts/verify_phase12.py yourdomain.com   # also scans your own domain
"""
from __future__ import annotations

import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

results: list[tuple[str, str]] = []


def record(status: str, name: str, detail: str = "") -> None:
    results.append((status, name))
    print(f"[{status}] {name}" + (f" - {detail}" if detail else ""))


REQUIRED_FILES = [
    "requirements.txt", "pytest.ini", "README.md",
    "app/main.py", "app/models.py", "app/domain.py", "app/dns_client.py",
    "app/scoring.py", "app/scanners/email_dns.py",
    "tests/fakes.py", "tests/test_domain.py", "tests/test_email_dns.py",
    "tests/test_scoring_and_api.py",
]


def check_python() -> None:
    ok = sys.version_info >= (3, 10)
    record("PASS" if ok else "FAIL", "Python 3.10 or newer", sys.version.split()[0])


def check_files() -> None:
    missing = [p for p in REQUIRED_FILES if not (ROOT / p).exists()]
    record("FAIL" if missing else "PASS", "Required files exist", ", ".join(missing))


def check_compile_and_import() -> None:
    r = subprocess.run([sys.executable, "-m", "compileall", "-q", "app"],
                       cwd=ROOT, capture_output=True, text=True)
    record("PASS" if r.returncode == 0 else "FAIL", "All code compiles", r.stdout[-300:] + r.stderr[-300:])
    try:
        import app.main  # noqa: F401
        record("PASS", "App imports")
    except Exception as exc:  # noqa: BLE001
        record("FAIL", "App imports", f"{type(exc).__name__}: {exc}")


def check_tests() -> None:
    r = subprocess.run([sys.executable, "-m", "pytest", "-q"], cwd=ROOT, capture_output=True, text=True)
    last = (r.stdout.strip().splitlines() or ["(no output)"])[-1]
    record("PASS" if r.returncode == 0 else "FAIL", "Automated tests", last)
    if r.returncode != 0:
        print(r.stdout[-2000:])


def check_scoring_logic() -> None:
    from app.scanners.email_dns import scan_email_domain
    from app.scoring import build_result
    from tests.fakes import FakeDns

    good = FakeDns(
        txt={"ok.com": ["v=spf1 include:_spf.google.com -all"],
             "_dmarc.ok.com": ["v=DMARC1; p=reject; rua=mailto:r@ok.com"],
             "google._domainkey.ok.com": ["v=DKIM1; p=ABC"]},
        mx={"ok.com": ["aspmx.l.google.com"]})
    bad = FakeDns()
    g = build_result("ok.com", scan_email_domain(good, "ok.com"))
    b = build_result("bad.com", scan_email_domain(bad, "bad.com"))
    ok = g.grade == "A" and g.score == 100 and b.score <= 60 and "spf-missing" in b.top_fixes
    record("PASS" if ok else "FAIL", "Scoring: good setup scores A, bad setup scores low",
           f"good={g.score}/{g.grade}, bad={b.score}/{b.grade}")


def check_live(extra_domain: str | None) -> None:
    from app.dns_client import DnsUnavailable, ResolverClient
    from app.domain import InvalidDomain, normalize_domain
    from app.scanners.email_dns import scan_email_domain
    from app.scoring import build_result

    dns = ResolverClient(timeout=4)
    try:
        if not dns.exists("example.com"):
            record("WARN", "Live DNS", "example.com not found. Your network may block or rewrite DNS; live checks skipped.")
            return
    except DnsUnavailable:
        record("WARN", "Live DNS", "lookups timed out; live checks skipped.")
        return
    record("PASS", "Live DNS reachable")

    try:
        fake = f"pixel7-no-such-domain-{uuid.uuid4().hex[:10]}.com"
        record("PASS" if not dns.exists(fake) else "WARN", "Unknown domains are detected",
               "" if not dns.exists(fake) else "your DNS provider answers for domains that do not exist")
        ids = {f.id for f in scan_email_domain(dns, "gmail.com")}
        ok = "mx-ok" in ids and any(i.startswith("spf-") for i in ids) and any(i.startswith("dmarc-") for i in ids)
        record("PASS" if ok else "FAIL", "Live scan of gmail.com finds MX, SPF and DMARC", ", ".join(sorted(ids)))

        from fastapi.testclient import TestClient
        from app.main import app
        res = TestClient(app).post("/api/scan/email", json={"domain": "gmail.com"})
        record("PASS" if res.status_code == 200 else "FAIL", "API works end to end with real DNS", f"HTTP {res.status_code}")

        if extra_domain:
            d = normalize_domain(extra_domain)
            r = build_result(d, scan_email_domain(dns, d))
            print(f"\n{d}: score {r.score}/100, grade {r.grade}")
            for f in r.findings:
                if f.status in ("fail", "warn"):
                    print(f"  - [{f.severity}] {f.title}")
            record("PASS", f"Scanned your domain {d}")
    except DnsUnavailable as exc:
        record("WARN", "Live checks interrupted", str(exc))
    except InvalidDomain as exc:
        record("FAIL", "Your domain was not valid", str(exc))
    except Exception as exc:  # noqa: BLE001
        record("FAIL", "Live checks crashed", f"{type(exc).__name__}: {exc}")


def main() -> int:
    extra = sys.argv[1] if len(sys.argv) > 1 else None
    steps = [check_python, check_files, check_compile_and_import, check_tests,
             check_scoring_logic, lambda: check_live(extra)]
    for step in steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001
            record("FAIL", getattr(step, "__name__", "check"), f"{type(exc).__name__}: {exc}")
    fails = [n for s, n in results if s == "FAIL"]
    warns = [n for s, n in results if s == "WARN"]
    print(f"\nSUMMARY: {len(results) - len(fails) - len(warns)} passed, {len(warns)} warnings, {len(fails)} failed")
    if fails:
        print("NOT READY for Phase 3. Fix these first:", "; ".join(fails))
        return 1
    if warns:
        print("Almost ready. Fix the warnings (usually network/DNS) and run again before relying on live results.")
    else:
        print("READY for Phase 3.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())