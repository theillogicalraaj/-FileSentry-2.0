from dataclasses import dataclass

@dataclass(frozen=True)
class Signature:
    name: str
    mime: str
    extension: str
    magic: bytes
    offset: int = 0

SIGNATURES = [
    Signature("JPEG image", "image/jpeg", ".jpg", bytes.fromhex("FFD8FF")),
    Signature("PNG image", "image/png", ".png", bytes.fromhex("89504E470D0A1A0A")),
    Signature("GIF image", "image/gif", ".gif", b"GIF8"),
    Signature("PDF document", "application/pdf", ".pdf", b"%PDF"),
    Signature("ZIP archive", "application/zip", ".zip", bytes.fromhex("504B0304")),
    Signature("GZIP archive", "application/gzip", ".gz", bytes.fromhex("1F8B")),
    Signature("RAR archive", "application/vnd.rar", ".rar", bytes.fromhex("526172211A07")),
    Signature("ELF executable", "application/x-elf", ".elf", bytes.fromhex("7F454C46")),
    Signature("Windows PE executable", "application/vnd.microsoft.portable-executable", ".exe", b"MZ"),
    Signature("WebP image", "image/webp", ".webp", b"RIFF", 0),
]

def detect_signature(data: bytes):
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return Signature("WebP image", "image/webp", ".webp", b"RIFF")
    for sig in SIGNATURES:
        if data[sig.offset:sig.offset+len(sig.magic)] == sig.magic:
            return sig
    return None
