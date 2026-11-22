from fastapi.testclient import TestClient

from app.main import app, get_dns
from app.models import Finding
from app.scoring import build_result, grade_for
from tests.fakes import FakeDns


def finding(id, status, severity):
    return Finding(id=id, category="c", title=id, status=status, severity=severity, summary="s")


def test_score_and_top_fixes_order():
    result = build_result("shop.com", [
        finding("ok", "pass", "info"),
        finding("low", "warn", "low"),
        finding("crit", "fail", "critical"),
        finding("high", "fail", "high"),
    ])
    assert result.score == 100 - 30 - 20 - 5
    assert result.top_fixes == ["crit", "high", "low"]
    assert result.findings[-1].id == "ok"  # passing checks listed last


def test_score_never_below_zero_and_grades():
    many = [finding(f"c{i}", "fail", "critical") for i in range(5)]
    assert build_result("x.com", many).score == 0
    assert [grade_for(s) for s in (95, 80, 65, 45, 10)] == ["A", "B", "C", "D", "F"]


def test_info_findings_do_not_cost_points():
    assert build_result("x.com", [finding("i", "info", "info")]).score == 100


def client_with(dns):
    app.dependency_overrides[get_dns] = lambda: dns
    return TestClient(app)


def test_api_scan_ok():
    dns = FakeDns(
        txt={"shop.com": ["v=spf1 include:_spf.google.com -all"],
             "_dmarc.shop.com": ["v=DMARC1; p=reject; rua=mailto:r@shop.com"],
             "google._domainkey.shop.com": ["v=DKIM1; p=ABC"]},
        mx={"shop.com": ["aspmx.l.google.com"]},
    )
    res = client_with(dns).post("/api/scan/email", json={"domain": "https://www.Shop.com/"})
    app.dependency_overrides.clear()
    body = res.json()
    assert res.status_code == 200
    assert body["domain"] == "shop.com" and body["grade"] == "A" and body["top_fixes"] == []


def test_api_invalid_domain():
    res = client_with(FakeDns()).post("/api/scan/email", json={"domain": "192.168.0.1"})
    app.dependency_overrides.clear()
    assert res.status_code == 422


def test_api_unknown_domain():
    res = client_with(FakeDns(exists=False)).post("/api/scan/email", json={"domain": "nothere.com"})
    app.dependency_overrides.clear()
    assert res.status_code == 404
