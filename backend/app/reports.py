import io, json
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch

def build_report(a) -> bytes:
    out = io.BytesIO()
    c = canvas.Canvas(out, pagesize=letter)
    y = 10.5 * inch
    c.setTitle(f"FileSentry Report #{a.id}")
    c.setFont("Helvetica-Bold", 18); c.drawString(0.7*inch, y, "FileSentry Forensic Report")
    y -= 0.35*inch; c.setFont("Helvetica", 10); c.drawString(0.7*inch, y, f"Case ID: FS-{a.id:08d}")
    y -= 0.3*inch
    rows = [
        ("File", a.original_name), ("Detected type", a.detected_type), ("Detected MIME", a.detected_mime),
        ("Claimed extension", a.claimed_extension or "<none>"), ("Size", f"{a.size_bytes:,} bytes"),
        ("SHA-256", a.sha256), ("Entropy", f"{a.entropy:.4f}"),
        ("Risk", f"{a.risk_level.upper()} ({a.risk_score}/100)"),
    ]
    for k, v in rows:
        if y < 0.9*inch: c.showPage(); y = 10.5*inch
        c.setFont("Helvetica-Bold", 9); c.drawString(0.7*inch, y, f"{k}:")
        c.setFont("Helvetica", 9); c.drawString(2.0*inch, y, str(v)[:100]); y -= 0.22*inch
    y -= 0.1*inch
    c.setFont("Helvetica-Bold", 11); c.drawString(0.7*inch, y, "Findings"); y -= 0.22*inch
    findings = json.loads(a.findings_json or "[]")
    c.setFont("Helvetica", 9)
    if not findings:
        c.drawString(0.9*inch, y, "No rule-based findings."); y -= 0.2*inch
    else:
        for f in findings:
            if y < 0.8*inch: c.showPage(); y = 10.5*inch; c.setFont("Helvetica", 9)
            text = f"[{f['severity'].upper()}] {f['message']}"
            c.drawString(0.9*inch, y, text[:115]); y -= 0.2*inch
    y -= 0.15*inch
    c.setFont("Helvetica-Oblique", 8)
    c.drawString(0.7*inch, y, "Defensive analysis only. High entropy or a mismatch is not, by itself, proof of malware.")
    c.save(); out.seek(0)
    return out.read()
