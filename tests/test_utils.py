from core.utils import fmt_bytes, fmt_ports, interval_stats, ip_scope, shannon_entropy, defang, safe_text, vowel_ratio


def test_entropy_bounds():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == 2.0
    assert shannon_entropy("q8vj2kz9xw3mt7pb5nh1d6") > shannon_entropy("wikipedia")


def test_ip_scope_documentation_ranges_are_external():
    assert ip_scope("192.168.1.5") == "internal"
    assert ip_scope("10.1.2.3") == "internal"
    assert ip_scope("203.0.113.9") == "external"      # RFC5737 documentation range treated as external
    assert ip_scope("224.0.0.251") == "special"
    assert ip_scope("not-an-ip") == "special"
    assert ip_scope("fe80::1") == "internal"


def test_fmt_ports_ranges():
    assert fmt_ports([1, 2, 3, 5, 9, 10]) == "1-3, 5, 9-10"
    assert fmt_ports([]) == ""


def test_interval_stats_regular_and_too_few():
    st = interval_stats([0, 60, 120, 180, 240])
    assert st["cv"] == 0 and st["jitter_ok"] == 1.0
    assert interval_stats([0, 1]) is None


def test_misc_helpers():
    assert fmt_bytes(2000) == "2.00 KB" and fmt_bytes(10_000_000) == "10.00 MB"
    assert defang("http://evil.example/a") == "hxxp://evil[.]example/a"
    assert "\x00" not in safe_text("a\x00b\x1bc") and len(safe_text("x" * 500, 50)) == 50
    assert vowel_ratio("bcdfg") == 0
