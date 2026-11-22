"""Thin wrapper around DNS lookups so the scanners are easy to test."""
from typing import Protocol

import dns.exception
import dns.resolver


class DnsUnavailable(RuntimeError):
    """The DNS lookup timed out or the name servers failed."""


class DomainNotFound(RuntimeError):
    """The domain does not exist."""


class DnsClient(Protocol):
    def txt(self, name: str) -> list[str]: ...
    def mx(self, name: str) -> list[str]: ...
    def exists(self, name: str) -> bool: ...


class ResolverClient:
    def __init__(self, timeout: float = 3.0):
        self._timeout = timeout

    def _resolver(self) -> dns.resolver.Resolver:
        # A fresh resolver per call keeps this safe to use from several threads.
        r = dns.resolver.Resolver()
        r.timeout = self._timeout
        r.lifetime = self._timeout
        return r

    def _query(self, name: str, rtype: str) -> list:
        try:
            return list(self._resolver().resolve(name, rtype))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            raise DnsUnavailable(f"DNS lookup failed for {name}") from exc

    def txt(self, name: str) -> list[str]:
        # A TXT record can be split into chunks; join them back together.
        return [b"".join(r.strings).decode("utf-8", "replace") for r in self._query(name, "TXT")]

    def mx(self, name: str) -> list[str]:
        return [str(r.exchange).rstrip(".").lower() for r in self._query(name, "MX")]

    def exists(self, name: str) -> bool:
        try:
            self._resolver().resolve(name, "A")
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except dns.resolver.NoAnswer:
            return True
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            raise DnsUnavailable(f"DNS lookup failed for {name}") from exc
