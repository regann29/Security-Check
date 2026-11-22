"""Email and domain checks: MX, SPF, DKIM and DMARC.

Only public DNS records are read. Nothing here touches the customer's servers.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

from ..dns_client import DnsClient, DnsUnavailable, DomainNotFound
from ..models import Finding

SERVICE = "Business Email & Domain Setup"
CATEGORY = "Email & Domain"

# DKIM keys live under a "selector" name that only the email provider knows.
# We try the most common ones. Not finding one does NOT prove DKIM is missing.
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2",
                  "mail", "s1", "s2", "dkim", "smtp", "mandrill"]

_SPF_LOOKUP_TERMS = {"include", "a", "mx", "ptr", "exists", "redirect"}


def _f(id, title, status, severity, summary, fix=None, technical=None) -> Finding:
    return Finding(id=id, category=CATEGORY, title=title, status=status, severity=severity,
                   summary=summary, fix=fix, technical=technical, service=SERVICE)


# ---------------------------------------------------------------- MX

def check_mx(dns: DnsClient, domain: str) -> list[Finding]:
    hosts = dns.mx(domain)
    real = [h for h in hosts if h]
    if real:
        return [_f("mx-ok", "Email receiving is set up", "pass", "info",
                   "Your domain is set up to receive email.", technical=", ".join(sorted(real)))]
    if hosts:  # only a "null MX" record
        return [_f("mx-null", "Domain says it does not receive email", "info", "info",
                   "Your domain is marked as not receiving email. That is fine if you do not use it for email.")]
    return [_f("mx-none", "No email receiving found", "info", "info",
               "We did not find email set up for this domain. If you use business email on it, this is worth checking.",
               technical=f"No MX records on {domain}.")]


# ---------------------------------------------------------------- SPF

def _spf_records(texts: list[str]) -> list[str]:
    return [t.strip() for t in texts if t.strip().lower().startswith("v=spf1")]


def count_spf_lookups(dns: DnsClient, record: str, path: frozenset = frozenset(), depth: int = 0) -> int:
    """Count the DNS lookups an SPF record causes, following includes."""
    if depth > 10:
        return 11
    total = 0
    for token in record.lower().split()[1:]:
        term = token.lstrip("+-~?")
        name = re.split(r"[:=/]", term, maxsplit=1)[0]
        if name not in _SPF_LOOKUP_TERMS:
            continue
        total += 1
        if name in ("include", "redirect") and re.search(r"[:=]", term):
            target = re.split(r"[:=]", term, maxsplit=1)[1]
            if target and target not in path:
                for rec in _spf_records(dns.txt(target)):
                    total += count_spf_lookups(dns, rec, path | {target}, depth + 1)
                    break
    return total


def check_spf(dns: DnsClient, domain: str) -> list[Finding]:
    records = _spf_records(dns.txt(domain))

    if not records:
        return [_f("spf-missing", "No sender list for your email (SPF)", "fail", "high",
                   "Your domain does not publish a list of who is allowed to send email in your name. "
                   "Scammers can send fake emails that look like they come from you, and your real emails "
                   "are more likely to end up in spam.",
                   "Publish an SPF record that lists the services you really send email from "
                   "(for example Google Workspace or Microsoft 365) and ends with -all.",
                   f"No TXT record starting with v=spf1 on {domain}.")]

    if len(records) > 1:
        return [_f("spf-multiple", "More than one sender list found", "fail", "high",
                   "Your domain has more than one SPF record. Mail systems treat this as an error and may "
                   "ignore all of them, so the protection does not work.",
                   "Merge them into one single SPF record.",
                   f"{len(records)} SPF records found.")]

    record = records[0]
    lowered = record.lower()
    issues: list[Finding] = []

    all_match = re.search(r"(?:^|\s)([+\-~?]?)all(?:\s|$)", lowered)
    has_redirect = re.search(r"(?:^|\s)redirect=", lowered) is not None

    if all_match:
        qualifier = all_match.group(1)
        if qualifier in ("", "+"):
            issues.append(_f("spf-allow-all", "Your sender list lets everyone in", "fail", "critical",
                             "Your SPF record ends with +all, which tells the world that any server may send "
                             "email as you. This is the same as having no protection at all.",
                             "Change +all to -all after listing your real senders.", record))
        elif qualifier == "?":
            issues.append(_f("spf-neutral", "Your sender list does not take a side", "fail", "high",
                             "Your SPF record says 'I don't know' about unlisted senders, so it blocks nothing.",
                             "Change ?all to -all after listing your real senders.", record))
        elif qualifier == "~":
            issues.append(_f("spf-softfail", "Your sender list is in 'soft' mode", "warn", "low",
                             "Fake emails are marked as suspicious but are usually still delivered. This is "
                             "common and acceptable, but a strict setting protects better.",
                             "Once all your real senders are listed, change ~all to -all.", record))
    elif not has_redirect:
        issues.append(_f("spf-no-ending", "Your sender list has no ending rule", "warn", "medium",
                         "Your SPF record does not say what to do with senders that are not listed, "
                         "so it gives little protection.",
                         "End the record with -all.", record))

    lookups = count_spf_lookups(dns, record)
    if lookups > 10:
        issues.append(_f("spf-too-many-lookups", "Your sender list is too long", "warn", "medium",
                         f"Your SPF record needs {lookups} lookups and the limit is 10. Some mail systems "
                         "will reject it, and then your real emails can fail checks.",
                         "Remove services you no longer use, or simplify the record.",
                         f"{lookups} DNS lookups (limit 10)."))

    if issues:
        return issues
    return [_f("spf-ok", "Sender list (SPF) is set up", "pass", "info",
               "Your domain lists who may send email for it and rejects the rest.", technical=record)]


# ---------------------------------------------------------------- DMARC

def _parse_tags(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


def check_dmarc(dns: DnsClient, domain: str) -> list[Finding]:
    texts = dns.txt(f"_dmarc.{domain}")
    records = [t.strip() for t in texts if t.strip().lower().replace(" ", "").startswith("v=dmarc1")]

    if not records:
        return [_f("dmarc-missing", "No policy against fake emails (DMARC)", "fail", "high",
                   "Nothing tells receiving mail systems what to do with fake emails that pretend to be you. "
                   "Scammers can impersonate your business, and big email providers increasingly expect "
                   "this to be in place.",
                   "Add a DMARC record. Start in watch mode (p=none) with a reports address, then move to "
                   "quarantine and finally reject.",
                   f"No DMARC record at _dmarc.{domain}.")]

    if len(records) > 1:
        return [_f("dmarc-multiple", "More than one fake-email policy found", "fail", "medium",
                   "Your domain has more than one DMARC record, so mail systems may ignore them.",
                   "Keep one DMARC record and remove the others.", f"{len(records)} records found.")]

    record = records[0]
    tags = _parse_tags(record)
    policy = tags.get("p", "").lower()
    findings: list[Finding] = []

    if policy == "none":
        findings.append(_f("dmarc-monitor-only", "Fake-email policy is in watch-only mode", "warn", "medium",
                           "You can receive reports, but fake emails are still delivered. This is a fine "
                           "first step, not the finish line.",
                           "After checking the reports, move the policy to quarantine, then reject.", record))
    elif policy in ("quarantine", "reject"):
        findings.append(_f("dmarc-ok", "Fake-email policy (DMARC) is active", "pass", "info",
                           f"Fake emails pretending to be you are set to be handled with '{policy}'.",
                           technical=record))
    else:
        findings.append(_f("dmarc-invalid", "Fake-email policy is incomplete", "fail", "medium",
                           "Your DMARC record exists but does not contain a valid policy, so it may be ignored.",
                           "Add a valid policy such as p=none, p=quarantine or p=reject.", record))

    pct = tags.get("pct")
    if policy in ("quarantine", "reject") and pct and pct.isdigit() and int(pct) < 100:
        findings.append(_f("dmarc-partial", "Policy covers only part of your email", "warn", "low",
                           f"Your policy applies to only {pct}% of messages.",
                           "Raise it to 100% once you are confident your real email passes.", record))

    if "rua" not in tags:
        findings.append(_f("dmarc-no-reports", "No reports about fake emails", "info", "info",
                           "You are not receiving reports about who is sending email as your domain.",
                           "Add a reports address (rua) so you can see misuse and fix problems.", record))
    return findings


# ---------------------------------------------------------------- DKIM

def _selector_has_key(dns: DnsClient, selector: str, domain: str) -> bool:
    try:
        for text in dns.txt(f"{selector}._domainkey.{domain}"):
            compact = text.lower().replace(" ", "")
            if "v=dkim1" in compact or "p=" in compact:
                return True
    except DnsUnavailable:
        pass
    return False


def check_dkim(dns: DnsClient, domain: str) -> list[Finding]:
    with ThreadPoolExecutor(max_workers=6) as pool:
        hits = list(pool.map(lambda s: _selector_has_key(dns, s, domain), DKIM_SELECTORS))
    found = [s for s, hit in zip(DKIM_SELECTORS, hits) if hit]

    if found:
        return [_f("dkim-found", "Email signing (DKIM) detected", "pass", "info",
                   "Emails from your domain are digitally signed, which helps prove they are genuine.",
                   technical="Selectors found: " + ", ".join(found))]
    return [_f("dkim-unconfirmed", "Could not confirm email signing (DKIM)", "info", "info",
               "We checked the most common setups and did not find email signing. It may still be set up "
               "under a custom name we cannot see from outside, so this is worth confirming.",
               "Ask whoever manages your email to confirm DKIM is turned on.",
               "No key found for common selectors; not proof that DKIM is missing.")]


# ---------------------------------------------------------------- entry point

def scan_email_domain(dns: DnsClient, domain: str) -> list[Finding]:
    if not dns.exists(domain):
        raise DomainNotFound(domain)
    findings: list[Finding] = []
    findings += check_mx(dns, domain)
    findings += check_spf(dns, domain)
    findings += check_dmarc(dns, domain)
    findings += check_dkim(dns, domain)
    return findings
