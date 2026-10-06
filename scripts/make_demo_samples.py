"""Create benign demo inputs for FileSentry.

These are synthetic byte sequences used to demonstrate signature detection;
they are not functional executables or real malware.
"""
from pathlib import Path
out = Path(__file__).resolve().parents[1] / "sample-files"
out.mkdir(exist_ok=True)
(out / "clean-photo.jpg").write_bytes(bytes.fromhex("FFD8FFE000") + b"DEMO-JPEG" * 100)
pe = bytearray(b"\x00" * 256)
pe[0:2] = b"MZ"
pe[0x3C:0x40] = (0x80).to_bytes(4, "little")
pe[0x80:0x84] = b"PE\x00\x00"
(out / "invoice.jpg").write_bytes(bytes(pe))
print("Created synthetic demo samples in", out)
