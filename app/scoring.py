"""Fixed scoring rules. No AI here, so the same input always gives the same score."""
from .models import Finding, ScanResult

_PENALTY = {"critical": 30, "high": 20, "medium": 10, "low": 5, "info": 0}
_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _is_problem(f: Finding) -> bool:
    return f.status in ("fail", "warn")


def grade_for(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def build_result(domain: str, findings: list[Finding]) -> ScanResult:
    problems = sorted((f for f in findings if _is_problem(f)), key=lambda f: _ORDER[f.severity])
    score = max(0, 100 - sum(_PENALTY[f.severity] for f in problems))
    ordered = sorted(findings, key=lambda f: (0 if _is_problem(f) else 1, _ORDER[f.severity]))
    return ScanResult(
        domain=domain,
        score=score,
        grade=grade_for(score),
        findings=ordered,
        top_fixes=[f.id for f in problems[:5]],
    )
