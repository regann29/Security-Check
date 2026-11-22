import pytest

from app.dns_client import DomainNotFound
from app.scanners.email_dns import (check_dkim, check_dmarc, check_mx, check_spf,
                                    count_spf_lookups, scan_email_domain)
from tests.fakes import FakeDns

D = "shop.com"


def ids(findings):
    return [f.id for f in findings]


# ---- SPF
def test_spf_missing():
    assert ids(check_spf(FakeDns(), D)) == ["spf-missing"]


def test_spf_multiple():
    dns = FakeDns(txt={D: ["v=spf1 -all", "v=spf1 include:x.com -all"]})
    assert ids(check_spf(dns, D)) == ["spf-multiple"]


@pytest.mark.parametrize("record,expected", [
    ("v=spf1 +all", "spf-allow-all"),
    ("v=spf1 all", "spf-allow-all"),
    ("v=spf1 ?all", "spf-neutral"),
    ("v=spf1 mx ~all", "spf-softfail"),
    ("v=spf1 mx", "spf-no-ending"),
    ("v=spf1 mx -all", "spf-ok"),
])
def test_spf_endings(record, expected):
    assert ids(check_spf(FakeDns(txt={D: [record]}), D)) == [expected]


def test_spf_redirect_is_not_flagged():
    dns = FakeDns(txt={D: ["v=spf1 redirect=_spf.provider.com"], "_spf.provider.com": ["v=spf1 mx -all"]})
    assert ids(check_spf(dns, D)) == ["spf-ok"]


def test_spf_too_many_lookups():
    includes = " ".join(f"include:s{i}.test.com" for i in range(11))
    dns = FakeDns(txt={D: [f"v=spf1 {includes} -all"]})
    assert "spf-too-many-lookups" in ids(check_spf(dns, D))


def test_spf_lookup_count_follows_includes():
    dns = FakeDns(txt={"a.com": ["v=spf1 include:b.com mx -all"], "b.com": ["v=spf1 a mx -all"]})
    assert count_spf_lookups(dns, "v=spf1 include:a.com -all") == 5


def test_spf_include_loop_does_not_hang():
    dns = FakeDns(txt={"a.com": ["v=spf1 include:b.com -all"], "b.com": ["v=spf1 include:a.com -all"]})
    assert count_spf_lookups(dns, "v=spf1 include:a.com -all") < 20


# ---- DMARC
def test_dmarc_missing():
    assert ids(check_dmarc(FakeDns(), D)) == ["dmarc-missing"]


def test_dmarc_monitor_only():
    dns = FakeDns(txt={f"_dmarc.{D}": ["v=DMARC1; p=none; rua=mailto:r@shop.com"]})
    assert ids(check_dmarc(dns, D)) == ["dmarc-monitor-only"]


def test_dmarc_reject_ok_without_reports():
    dns = FakeDns(txt={f"_dmarc.{D}": ["v=DMARC1; p=reject"]})
    assert ids(check_dmarc(dns, D)) == ["dmarc-ok", "dmarc-no-reports"]


def test_dmarc_partial():
    dns = FakeDns(txt={f"_dmarc.{D}": ["v=DMARC1; p=quarantine; pct=25; rua=mailto:r@shop.com"]})
    assert ids(check_dmarc(dns, D)) == ["dmarc-ok", "dmarc-partial"]


def test_dmarc_invalid_policy():
    dns = FakeDns(txt={f"_dmarc.{D}": ["v=DMARC1; rua=mailto:r@shop.com"]})
    assert ids(check_dmarc(dns, D)) == ["dmarc-invalid"]


# ---- DKIM
def test_dkim_found():
    dns = FakeDns(txt={f"google._domainkey.{D}": ["v=DKIM1; k=rsa; p=ABC"]})
    result = check_dkim(dns, D)
    assert ids(result) == ["dkim-found"] and "google" in result[0].technical


def test_dkim_not_confirmed_is_not_a_failure():
    result = check_dkim(FakeDns(), D)
    assert ids(result) == ["dkim-unconfirmed"] and result[0].status == "info"


# ---- MX
def test_mx_variants():
    assert ids(check_mx(FakeDns(mx={D: ["mx.google.com"]}), D)) == ["mx-ok"]
    assert ids(check_mx(FakeDns(mx={D: [""]}), D)) == ["mx-null"]
    assert ids(check_mx(FakeDns(), D)) == ["mx-none"]


# ---- whole scan
def test_unknown_domain_raises():
    with pytest.raises(DomainNotFound):
        scan_email_domain(FakeDns(exists=False), D)


def test_full_scan_runs_all_checks():
    got = ids(scan_email_domain(FakeDns(), D))
    assert {"mx-none", "spf-missing", "dmarc-missing", "dkim-unconfirmed"} <= set(got)
