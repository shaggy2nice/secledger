from __future__ import annotations

from secledger.models import Finding
from secledger.signature import default_signature, normalize_location, signature_of


def mk(**kw) -> Finding:
    base = {"id": "x", "title": "t"}
    base.update(kw)
    return Finding.from_dict(base)


def test_normalize_strips_method_scheme_host_query():
    assert normalize_location("GET https://h.example/api/x?y=1") == "/api/x"
    assert normalize_location("POST https://h.example/api/x") == "/api/x"
    assert normalize_location("https://h.example/api//x/") == "/api/x"


def test_normalize_file_location_drops_line_number():
    assert normalize_location("src/app/routes.py:42") == "src/app/routes.py"


def test_same_bug_different_wording_same_signature():
    a = mk(category="xss", location="GET https://dev.test/search?q=1")
    b = mk(category="XSS", location="https://dev.test/search")
    assert default_signature(a) == default_signature(b) == "xss::/search"


def test_fingerprint_takes_precedence():
    a = mk(category="sqli", location="/a", fingerprint="FP-1")
    b = mk(category="xss", location="/totally-different", fingerprint="FP-1")
    assert signature_of(a) == signature_of(b) == "fp::FP-1"


def test_distinct_locations_distinct_signatures():
    a = mk(category="xss", location="/search")
    b = mk(category="xss", location="/profile")
    assert default_signature(a) != default_signature(b)
