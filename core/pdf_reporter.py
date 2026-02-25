"""
PDF Report Generator
Professional-grade PDF security assessment report using HTML-to-PDF conversion.
Falls back to HTML if weasyprint/pdfkit not available.
"""
import os
from datetime import datetime
from collections import Counter


def generate_pdf_report(target, findings, assessor="LOCKON Operator"):
    """Generate a professional PDF security report.
    
    Strategy: Generate styled HTML → convert to PDF via weasyprint.
    If weasyprint unavailable, falls back to saving HTML with print CSS.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = f.get('severity', 'Info')
        if sev in stats: stats[sev] += 1
        else: stats["Info"] += 1
    
    total = len(findings)
    risk_score = min(100, int(stats["Critical"] * 20 + stats["High"] * 10 + stats["Medium"] * 5 + stats["Low"] * 2 + stats["Info"] * 0.5))
    risk_label = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 30 else "LOW"
    risk_color = "#d32f2f" if risk_score >= 80 else "#f44336" if risk_score >= 60 else "#ff9800" if risk_score >= 30 else "#4caf50"
    
    # OWASP Coverage
    owasp_categories = {
        "A01:2021": "Broken Access Control", "A02:2021": "Cryptographic Failures",
        "A03:2021": "Injection", "A04:2021": "Insecure Design",
        "A05:2021": "Security Misconfiguration", "A06:2021": "Vulnerable Components",
        "A07:2021": "Auth Failures", "A08:2021": "Software Integrity",
        "A09:2021": "Logging Failures", "A10:2021": "SSRF"
    }
    owasp_hits = Counter()
    for f in findings:
        owasp = f.get('owasp', '')
        if owasp:
            for code in owasp_categories:
                if code in owasp:
                    owasp_hits[code] += 1
    
    sorted_findings = sorted(findings, key=lambda x: x.get('cvss_score', 0), reverse=True)
    
    # Build PDF-optimized HTML
    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Security Assessment - {target}</title>
<style>
    @page {{ size: A4; margin: 20mm 15mm; }}
    body {{ font-family: 'Segoe UI', Arial, sans-serif; color: #222; font-size: 10pt; line-height: 1.5; }}
    h1 {{ color: #1a237e; font-size: 18pt; }}
    h2 {{ color: #1a237e; font-size: 13pt; border-bottom: 2px solid #1a237e; padding-bottom: 5px; margin-top: 20px; }}
    h3 {{ color: #333; font-size: 11pt; margin-top: 15px; }}
    
    /* Cover Page */
    .cover {{ page-break-after: always; text-align: center; padding-top: 200px; }}
    .cover h1 {{ font-size: 28pt; color: #0d47a1; letter-spacing: 3px; }}
    .cover .subtitle {{ font-size: 16pt; color: #555; margin-top: 10px; }}
    .cover .meta-table {{ margin: 40px auto; text-align: left; border-collapse: collapse; }}
    .cover .meta-table td {{ padding: 8px 15px; border-bottom: 1px solid #ddd; }}
    .cover .meta-table td:first-child {{ font-weight: bold; color: #1a237e; }}
    .cover .confidential {{ color: #d32f2f; font-weight: bold; font-size: 12pt; margin-top: 80px; }}
    
    /* Stats */
    .stats-row {{ display: flex; gap: 10px; margin: 15px 0; }}
    .stat-box {{ flex: 1; text-align: center; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }}
    .stat-box .num {{ font-size: 18pt; font-weight: bold; }}
    .stat-box .label {{ font-size: 8pt; color: #666; text-transform: uppercase; }}
    
    /* Risk */
    .risk-box {{ display: inline-block; padding: 8px 20px; border: 2px solid {risk_color}; border-radius: 6px; margin: 10px 0; }}
    .risk-box .score {{ font-size: 20pt; font-weight: bold; color: {risk_color}; }}
    .risk-box .label {{ font-size: 9pt; color: #666; }}
    
    /* OWASP */
    .owasp-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 6px; margin: 10px 0; }}
    .owasp-item {{ border: 1px solid #ddd; border-radius: 4px; padding: 6px; text-align: center; font-size: 8pt; }}
    .owasp-item.found {{ border-color: #ff9800; background: #fff8e1; }}
    .owasp-code {{ font-family: monospace; font-weight: bold; }}
    .owasp-count {{ font-size: 12pt; font-weight: bold; color: #ff9800; }}
    
    /* Findings */
    .finding {{ border: 1px solid #ddd; border-radius: 5px; margin-bottom: 15px; page-break-inside: avoid; }}
    .finding-head {{ padding: 8px 12px; background: #f5f5f5; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #ddd; }}
    .finding-head .title {{ font-weight: bold; font-family: Consolas, monospace; font-size: 10pt; }}
    .finding-body {{ padding: 12px; }}
    
    .badge {{ padding: 2px 6px; border-radius: 3px; font-size: 8pt; font-weight: bold; color: #fff; }}
    .sev-critical {{ background: #d32f2f; }} .sev-high {{ background: #f44336; }}
    .sev-medium {{ background: #ff9800; color: #000; }} .sev-low {{ background: #4caf50; }} .sev-info {{ background: #2196f3; }}
    .badge-meta {{ background: #f5f5f5; border: 1px solid #ddd; color: #333; margin-right: 4px; }}
    
    pre {{ background: #f5f5f5; padding: 8px; border-radius: 3px; font-size: 8pt; overflow-wrap: break-word; white-space: pre-wrap; border: 1px solid #eee; }}
    
    .remediation {{ background: #e8f5e9; border: 1px solid #c8e6c9; border-radius: 4px; padding: 10px; margin-top: 10px; }}
    .remediation h4 {{ color: #2e7d32; font-size: 9pt; margin-bottom: 6px; }}
    .remediation ol {{ padding-left: 18px; font-size: 9pt; }}
    .remediation li {{ margin-bottom: 3px; }}
    
    .footer {{ text-align: center; color: #999; font-size: 8pt; margin-top: 30px; border-top: 1px solid #ddd; padding-top: 10px; }}
    table.detail {{ width: 100%; border-collapse: collapse; font-size: 9pt; margin: 5px 0; }}
    table.detail td {{ padding: 4px 8px; border-bottom: 1px solid #eee; }}
    table.detail td:first-child {{ width: 120px; font-weight: bold; color: #555; }}
</style>
</head>
<body>

<!-- COVER PAGE -->
<div class="cover">
    <h1>LOCKON ORBITAL STRIKE</h1>
    <div class="subtitle">Security Assessment Report</div>
    <table class="meta-table">
        <tr><td>Target</td><td>{target}</td></tr>
        <tr><td>Assessment Date</td><td>{timestamp}</td></tr>
        <tr><td>Assessor</td><td>{assessor}</td></tr>
        <tr><td>Total Findings</td><td>{total}</td></tr>
        <tr><td>Risk Score</td><td style="color:{risk_color}; font-weight:bold;">{risk_score}/100 ({risk_label})</td></tr>
    </table>
    <div class="confidential">CONFIDENTIAL — FOR AUTHORIZED RECIPIENTS ONLY</div>
</div>

<!-- EXECUTIVE SUMMARY -->
<h2>1. Executive Summary</h2>
<p>An automated security assessment was performed against <strong>{target}</strong> on {timestamp}. 
The assessment identified <strong>{total}</strong> security findings with the following severity distribution:</p>

<div class="risk-box">
    <div class="score">{risk_score}</div>
    <div class="label">RISK SCORE / 100</div>
</div>

<div class="stats-row">
    <div class="stat-box"><div class="num" style="color:#d32f2f;">{stats['Critical']}</div><div class="label">Critical</div></div>
    <div class="stat-box"><div class="num" style="color:#f44336;">{stats['High']}</div><div class="label">High</div></div>
    <div class="stat-box"><div class="num" style="color:#ff9800;">{stats['Medium']}</div><div class="label">Medium</div></div>
    <div class="stat-box"><div class="num" style="color:#4caf50;">{stats['Low']}</div><div class="label">Low</div></div>
    <div class="stat-box"><div class="num" style="color:#2196f3;">{stats['Info']}</div><div class="label">Info</div></div>
</div>

<!-- OWASP COVERAGE -->
<h2>2. OWASP Top 10 (2021) Coverage</h2>
<div class="owasp-grid">
"""
    
    for code, name in owasp_categories.items():
        count = owasp_hits.get(code, 0)
        cls = "owasp-item found" if count > 0 else "owasp-item"
        html += f'<div class="{cls}"><div class="owasp-code">{code}</div><div>{name}</div><div class="owasp-count">{count if count else "-"}</div></div>\n'
    
    html += """</div>

<!-- DETAILED FINDINGS -->
<h2>3. Detailed Findings</h2>
"""
    
    for idx, f in enumerate(sorted_findings, 1):
        severity = f.get('severity', 'Info').capitalize()
        sev_cls = f"sev-{severity.lower()}"
        cvss_score = f.get('cvss_score', 0)
        cvss_vector = f.get('cvss_vector', '')
        cwe_id = f.get('cwe', '')
        owasp_ref = f.get('owasp', '')
        
        meta_badges = ""
        if cvss_score: meta_badges += f'<span class="badge badge-meta">CVSS {cvss_score}</span> '
        if cwe_id: meta_badges += f'<span class="badge badge-meta">{cwe_id}</span> '
        if owasp_ref: meta_badges += f'<span class="badge badge-meta">{owasp_ref}</span> '
        
        evidence_text = str(f.get('evidence', 'N/A')).replace('<', '&lt;').replace('>', '&gt;')
        
        # Remediation
        remediation_html = ""
        rg = f.get('remediation_guide', {})
        if isinstance(rg, dict) and rg.get('fix_steps'):
            steps = "".join(f"<li>{s}</li>" for s in rg['fix_steps'])
            remediation_html = f'<div class="remediation"><h4>Remediation</h4><ol>{steps}</ol></div>'
        
        html += f"""
        <div class="finding">
            <div class="finding-head">
                <span class="title">{idx}. {f.get('type')}</span>
                <span class="badge {sev_cls}">{severity.upper()}</span>
            </div>
            <div class="finding-body">
                <div style="margin-bottom:8px;">{meta_badges}</div>
                <table class="detail">
                    <tr><td>Description</td><td>{f.get('detail', 'N/A')}</td></tr>
                    {'<tr><td>CVSS Vector</td><td style="font-family:monospace;">' + cvss_vector + '</td></tr>' if cvss_vector else ''}
                </table>
                <h4 style="font-size:9pt; color:#555; margin-top:10px;">Evidence</h4>
                <pre>{evidence_text}</pre>
                {remediation_html}
            </div>
        </div>
        """
    
    html += f"""
<!-- APPENDIX -->
<h2>4. Appendix</h2>
<h3>4.1 Methodology</h3>
<p style="font-size:9pt;">This assessment was conducted using LOCKON ORBITAL STRIKE, an automated web application security scanner. 
The tool performs active and passive testing across multiple vulnerability categories including injection flaws, 
authentication issues, security misconfigurations, and more.</p>

<h3>4.2 Severity Classification</h3>
<table class="detail" style="margin-top:5px;">
    <tr><td>Critical (9.0-10.0)</td><td>Immediate exploitation possible. Direct compromise of system confidentiality, integrity, or availability.</td></tr>
    <tr><td>High (7.0-8.9)</td><td>Exploitation likely. Significant impact on security posture.</td></tr>
    <tr><td>Medium (4.0-6.9)</td><td>Exploitation possible under specific conditions. Moderate impact.</td></tr>
    <tr><td>Low (0.1-3.9)</td><td>Limited impact. Exploitation requires significant effort or unlikely conditions.</td></tr>
    <tr><td>Info (0.0)</td><td>Informational finding with no direct security impact.</td></tr>
</table>

<div class="footer">
    LOCKON ORBITAL STRIKE — Security Assessment Report | Generated: {timestamp} | CONFIDENTIAL
</div>

</body>
</html>"""
    
    if not os.path.exists("reports"):
        os.makedirs("reports")
    
    # Try weasyprint first for PDF
    pdf_path = os.path.join("reports", f"report_{date_str}.pdf")
    try:
        from weasyprint import HTML as WeasyHTML
        WeasyHTML(string=html).write_pdf(pdf_path)
        return pdf_path
    except ImportError:
        pass
    
    # Fallback: try pdfkit
    try:
        import pdfkit
        pdfkit.from_string(html, pdf_path)
        return pdf_path
    except (ImportError, OSError):
        pass
    
    # Final fallback: save as print-ready HTML
    html_path = os.path.join("reports", f"report_printable_{date_str}.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    return html_path
