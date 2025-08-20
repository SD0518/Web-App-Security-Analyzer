from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import io

def generate_report_bytes(results_dict):
    """
    Build a PDF report and return it as bytes.

    results_dict expects keys:
    - target: str
    - security_headers: dict[str, str]
    - vulnerabilities: dict[str, str]
    - tls_https: dict[str, str] | None
    - cookies: list[dict[name, Secure, HttpOnly, SameSite]]
    - robots: list[str]
    """
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    y = height - 50
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "Web App Security Analyzer Report")

    y -= 30
    c.setFont("Helvetica", 12)
    c.drawString(50, y, f"Target: {results_dict.get('target', '-')}")

    # Security Headers
    y -= 40
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Security Headers")
    c.setFont("Helvetica", 12)
    for k, v in results_dict.get("security_headers", {}).items():
        y -= 20
        c.drawString(60, y, f"{k}: {v}")

    # Vulnerabilities
    y -= 40
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Vulnerability Detection")
    c.setFont("Helvetica", 12)
    for k, v in results_dict.get("vulnerabilities", {}).items():
        y -= 20
        c.drawString(60, y, f"{k}: {v}")

    # TLS/HTTPS
    tls = results_dict.get("tls_https") or {}
    if tls:
        y -= 40
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "TLS/HTTPS Scan")
        c.setFont("Helvetica", 12)
        for k, v in tls.items():
            y -= 20
            c.drawString(60, y, f"{k}: {v}")

    # Cookies
    cookies = results_dict.get("cookies") or []
    if cookies:
        y -= 40
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "Cookie Security Flags")
        c.setFont("Helvetica", 12)
        for cookie in cookies:
            y -= 20
            c.drawString(
                60,
                y,
                f"{cookie.get('name','-')} - Secure: {cookie.get('Secure','-')}, HttpOnly: {cookie.get('HttpOnly','-')}, SameSite: {cookie.get('SameSite','-')}"
            )

    # Robots.txt
    robots = results_dict.get("robots") or []
    if robots:
        y -= 40
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "robots.txt & Path Probing")
        c.setFont("Helvetica", 12)
        for line in robots[:12]:
            y -= 20
            c.drawString(60, y, line)
        if len(robots) > 12:
            y -= 20
            c.drawString(60, y, f"... and {len(robots) - 12} more lines")

    c.save()
    buffer.seek(0)
    return buffer.getvalue()


def generate_report(results, filename="scan_report.pdf"):
    data = generate_report_bytes(results)
    with open(filename, "wb") as f:
        f.write(data)
