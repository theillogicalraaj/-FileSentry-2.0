import hashlib, json, math, mimetypes
from pathlib import Path
from .signatures import detect_signature


def shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = [0] * 256
    for b in data: counts[b] += 1
    length = len(data)
    return round(-sum((c/length) * math.log2(c/length) for c in counts if c), 4)


def hashes(data: bytes):
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


def pe_indicators(data: bytes) -> dict:
    out = {"is_pe": False, "machine": None, "pe_offset": None}
    if data[:2] != b"MZ" or len(data) < 0x40: return out
    pe_offset = int.from_bytes(data[0x3C:0x40], "little", signed=False)
    out["pe_offset"] = pe_offset
    if 0 <= pe_offset <= len(data) - 4 and data[pe_offset:pe_offset+4] == b"PE\\x00\\x00":
        out["is_pe"] = True
        if len(data) >= pe_offset + 6:
            out["machine"] = "0x%04x" % int.from_bytes(data[pe_offset+4:pe_offset+6], "little")
    return out


def elf_indicators(data: bytes) -> dict:
    out = {"is_elf": False, "class": None, "endianness": None}
    if not data.startswith(b"\\x7fELF") or len(data) < 6: return out
    out["is_elf"] = True
    out["class"] = {1: "32-bit", 2: "64-bit"}.get(data[4], "unknown")
    out["endianness"] = {1: "little", 2: "big"}.get(data[5], "unknown")
    return out


def sliding_entropy(data: bytes, window: int = 4096, limit: int = 32):
    if not data: return []
    values = []
    for i in range(0, min(len(data), window * limit), window):
        values.append({"offset": i, "entropy": shannon_entropy(data[i:i+window])})
    return values


def analyze_file(path: Path):
    data = path.read_bytes()
    ext = path.suffix.lower() if path.suffix else None
    claimed_mime = mimetypes.guess_type(path.name)[0]
    sig = detect_signature(data)
    h = hashes(data)
    entropy = shannon_entropy(data)
    findings = []
    indicators = {"entropy_windows": sliding_entropy(data), "pe": pe_indicators(data), "elf": elf_indicators(data)}
    detected_type = sig.name if sig else "Unknown binary / unrecognized format"
    detected_mime = sig.mime if sig else (claimed_mime or "application/octet-stream")
    confidence = 96 if sig else 45

    if sig and ext != sig.extension:
        findings.append({"severity": "high", "code": "EXTENSION_MISMATCH", "message": f"Filename extension {ext or '<none>'} does not match detected type {sig.extension}."})
    if indicators["pe"]["is_pe"]:
        findings.append({"severity": "info", "code": "PE_STRUCTURE", "message": "Portable Executable structure detected from the binary header."})
    if indicators["elf"]["is_elf"]:
        findings.append({"severity": "info", "code": "ELF_STRUCTURE", "message": f"ELF executable structure detected ({indicators['elf']['class']})."})
    if entropy >= 7.5:
        findings.append({"severity": "medium", "code": "HIGH_ENTROPY", "message": f"High global Shannon entropy ({entropy:.2f}/8.0). This can be consistent with compression or encryption and is not proof of malware."})
    if ext and ext.count(".") == 0 and sig:
        findings.append({"severity": "low", "code": "MISSING_EXTENSION", "message": "The file has no extension but a known binary signature."})
    if path.name.lower().count(".") >= 2 and ext in {".jpg", ".png", ".pdf", ".doc", ".docx", ".xls", ".xlsx"}:
        findings.append({"severity": "medium", "code": "DOUBLE_EXTENSION", "message": "Multiple filename extensions detected; review the original acquisition context."})

    score = 0
    weights = {"high": 40, "medium": 15, "low": 5, "info": 0}
    for f in findings: score += weights.get(f["severity"], 0)
    if not sig: score += 10
    score = min(score, 100)
    level = "critical" if score >= 76 else "high" if score >= 51 else "medium" if score >= 21 else "low"
    return {
        "size_bytes": len(data), "claimed_extension": ext, "claimed_mime": claimed_mime,
        "detected_type": detected_type, "detected_mime": detected_mime,
        "confidence": confidence, **h, "entropy": entropy,
        "risk_score": score, "risk_level": level,
        "findings": findings, "indicators": indicators,
    }
