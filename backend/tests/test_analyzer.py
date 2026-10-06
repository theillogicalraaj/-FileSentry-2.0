from pathlib import Path
from app.analyzer import analyze_file, shannon_entropy

def test_jpeg_signature(tmp_path: Path):
    p = tmp_path / "photo.jpg"
    p.write_bytes(bytes.fromhex("FFD8FFE000") + b"abc" * 100)
    r = analyze_file(p)
    assert r["detected_type"] == "JPEG image"
    assert r["risk_level"] == "low"

def test_extension_mismatch(tmp_path: Path):
    p = tmp_path / "photo.jpg"
    p.write_bytes(b"MZ" + b"\\x00" * 200)
    r = analyze_file(p)
    assert r["detected_type"] == "Windows PE executable"
    assert any(f["code"] == "EXTENSION_MISMATCH" for f in r["findings"])
    assert r["risk_score"] >= 40

def test_entropy_empty():
    assert shannon_entropy(b"") == 0.0
