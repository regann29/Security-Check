from typing import Literal

from pydantic import BaseModel

Severity = Literal["critical", "high", "medium", "low", "info"]
Status = Literal["pass", "warn", "fail", "info"]


class Finding(BaseModel):
    """One result from a check, written so a non-technical person can read it."""

    id: str
    category: str
    title: str
    status: Status
    severity: Severity
    summary: str  # plain language: what it means for the business
    fix: str | None = None  # plain language: what to do
    technical: str | None = None  # raw detail for technical readers
    service: str | None = None  # which PIXEL7 service fixes this


class ScanResult(BaseModel):
    domain: str
    score: int
    grade: str
    findings: list[Finding]
    top_fixes: list[str]  # finding ids, most important first
