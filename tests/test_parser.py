import pytest

from core.pcap_parser import (PcapValidationError, parse_client_hello, parse_http, parse_pcap, validate_file, classify_payload)
from sample_data.generate_samples import build_client_hello, generate_all


@pytest.fixture(scope="module")
def samples(tmp_path_factory):
    d = tmp_path_factory.mktemp("samples")
    return {p.name: p for p in generate_all(d)}


def test_validation_errors(tmp_path):
    with pytest.raises(PcapValidationError):
        validate_file(tmp_path / "missing.pcap")
    bad_ext = tmp_path / "a.txt"
    bad_ext.write_bytes(b"x" * 100)
    with pytest.raises(PcapValidationError, match="Unsupported"):
        validate_file(bad_ext)
    bad_magic = tmp_path / "a.pcap"
    bad_magic.write_bytes(b"NOTAPCAP" * 20)
    with pytest.raises(PcapValidationError, match="magic"):
        validate_file(bad_magic)
    empty = tmp_path / "e.pcap"
    empty.write_bytes(b"")
    with pytest.raises(PcapValidationError):
        validate_file(empty)


def test_size_limit(samples):
    with pytest.raises(PcapValidationError, match="limit"):
        validate_file(samples["exfil_sim.pcap"], max_mb=1)


def test_parse_pcap_and_pcapng(samples):
    df, meta = parse_pcap(samples["beacon_sim.pcap"])
    assert meta["format"] == "pcap" and meta["packets"] == len(df) > 100
    assert df["tls_sni"].notna().any() and df["tls_ja3"].notna().any()
    if "demo_combined_sim.pcapng" in samples:
        _, m2 = parse_pcap(samples["demo_combined_sim.pcapng"])
        assert m2["format"] == "pcapng" and m2["packets"] > 1000


def test_truncated_capture_is_handled(samples, tmp_path):
    data = samples["beacon_sim.pcap"].read_bytes()
    t = tmp_path / "trunc.pcap"
    t.write_bytes(data[: len(data) // 2 + 7])
    df, meta = parse_pcap(t)
    assert meta["packets"] > 0   # partial results, no crash


def test_garbage_after_header_does_not_crash(tmp_path):
    g = tmp_path / "g.pcap"
    g.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 16 + b"\xff" * 64)
    try:
        df, meta = parse_pcap(g)
        assert meta["packets"] == 0 or meta["warnings"]
    except PcapValidationError:
        pass


def test_max_packets_limit(samples):
    df, meta = parse_pcap(samples["beacon_sim.pcap"], max_packets=50)
    assert meta["truncated"] and len(df) == 50


def test_client_hello_sni_and_ja3_stable():
    h1 = parse_client_hello(build_client_hello("Example.TEST"))
    h2 = parse_client_hello(build_client_hello("other.test"))
    assert h1["sni"] == "example.test" and h1["version"] == "TLS 1.3"
    assert h1["ja3"] == h2["ja3"]               # same client parameters -> same fingerprint
    assert parse_client_hello(b"\x16\x03\x01\x00") is None
    assert parse_client_hello(b"GET / HTTP/1.1") is None


def test_http_parser_keeps_headers_only():
    r = parse_http(b"POST /up?x=1 HTTP/1.1\r\nHost: A.example\r\nUser-Agent: curl/8\r\nContent-Length: 99\r\n\r\nSECRETBODY")
    assert r["method"] == "POST" and r["host"] == "a.example" and r["clen"] == 99
    assert "SECRETBODY" not in str(r)
    assert parse_http(b"HTTP/1.1 404 Not Found\r\n\r\n")["status"] == 404
    assert parse_http(b"\x00\x01binary") is None


def test_classify_payload():
    assert classify_payload(b"SSH-2.0-OpenSSH_9\r\n")[0] == "SSH"
    assert classify_payload(b"\x00\x00\x00\x10\xfeSMB" + b"\x00" * 8)[0] == "SMB"
    assert classify_payload(b"")[0] is None
