import pytest

from app.domain import InvalidDomain, normalize_domain


@pytest.mark.parametrize("raw,expected", [
    ("Example.com", "example.com"),
    ("https://www.shop.com/about?x=1", "shop.com"),
    ("info@clinic.org", "clinic.org"),
    ("shop.com.", "shop.com"),
    ("  school.edu.np  ", "school.edu.np"),
])
def test_cleans_input(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "localhost", "192.168.1.1", "10.0.0.5", "nodot", "bad_name.com",
    "-start.com", "server.local", "site.internal", "a..b.com", "x" * 70 + ".com",
])
def test_rejects_bad_input(raw):
    with pytest.raises(InvalidDomain):
        normalize_domain(raw)
