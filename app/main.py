from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from .dns_client import DnsClient, DnsUnavailable, DomainNotFound, ResolverClient
from .domain import InvalidDomain, normalize_domain
from .models import ScanResult
from .scanners.email_dns import scan_email_domain
from .scoring import build_result

app = FastAPI(title="PIXEL7 Security Health Check", version="0.1.0")


class ScanRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=300)


def get_dns() -> DnsClient:
    return ResolverClient()


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


# Note: these checks read public DNS records only. Ownership verification
# (Phase 5) and rate limiting must be added before any scan that touches a
# customer's own servers.
@app.post("/api/scan/email", response_model=ScanResult)
def scan_email(req: ScanRequest, dns: DnsClient = Depends(get_dns)) -> ScanResult:
    try:
        domain = normalize_domain(req.domain)
        findings = scan_email_domain(dns, domain)
    except InvalidDomain as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except DomainNotFound:
        raise HTTPException(status_code=404, detail="We could not find that domain. Please check the spelling.")
    except DnsUnavailable:
        raise HTTPException(status_code=503, detail="We could not reach the domain's name servers. Please try again.")
    return build_result(domain, findings)
