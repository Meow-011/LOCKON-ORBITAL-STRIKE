import os
import json
from datetime import datetime
from collections import Counter

def generate_html_report(target, findings):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = f.get('severity', 'Info')
        if sev in stats: stats[sev] += 1
        else: stats["Info"] += 1
    
    total = len(findings)
    
    # Risk Score (weighted)
    risk_score = min(100, (stats["Critical"] * 20 + stats["High"] * 10 + stats["Medium"] * 5 + stats["Low"] * 2 + stats["Info"] * 0.5))
    risk_label = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 30 else "LOW"
    risk_color = "#d32f2f" if risk_score >= 80 else "#f44336" if risk_score >= 60 else "#ff9800" if risk_score >= 30 else "#4caf50"
    
    # OWASP Coverage Matrix
    owasp_categories = {
        "A01:2021": "Broken Access Control",
        "A02:2021": "Cryptographic Failures", 
        "A03:2021": "Injection",
        "A04:2021": "Insecure Design",
        "A05:2021": "Security Misconfiguration",
        "A06:2021": "Vulnerable Components",
        "A07:2021": "Auth Failures",
        "A08:2021": "Software/Data Integrity",
        "A09:2021": "Logging/Monitoring",
        "A10:2021": "SSRF"
    }
    owasp_hits = Counter()
    for f in findings:
        owasp = f.get('owasp', '')
        if owasp:
            for code in owasp_categories:
                if code in owasp:
                    owasp_hits[code] += 1
    
    # Top CVSS findings
    sorted_findings = sorted(findings, key=lambda x: x.get('cvss_score', 0), reverse=True)

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>LOCKON ORBITAL STRIKE — Security Assessment Report</title>
        <style>
            * {{ margin:0; padding:0; box-sizing:border-box; }}
            body {{ font-family: 'Segoe UI', -apple-system, sans-serif; background: #0a0a0f; color: #e0e0e0; }}
            .container {{ max-width: 1100px; margin: 0 auto; padding: 30px; }}
            
            /* Header */
            .report-header {{ border-bottom: 2px solid #00e5ff33; padding: 30px 0; margin-bottom: 30px; }}
            .report-header h1 {{ color: #00e5ff; font-size: 1.6em; letter-spacing: 2px; font-family: Consolas, monospace; }}
            .report-header .meta {{ color: #888; font-size: 0.85em; margin-top: 8px; }}
            .report-header .meta span {{ margin-right: 15px; }}
            
            /* Executive Summary */
            .exec-summary {{ background: #111118; border: 1px solid #222; border-radius: 8px; padding: 25px; margin-bottom: 25px; }}
            .exec-summary h2 {{ color: #00e5ff; font-size: 1.1em; margin-bottom: 15px; letter-spacing: 1px; }}
            .risk-gauge {{ display: flex; align-items: center; gap: 20px; margin-bottom: 20px; }}
            .risk-circle {{ width: 80px; height: 80px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-direction: column; border: 3px solid {risk_color}; }}
            .risk-circle .score {{ font-size: 1.3em; font-weight: bold; color: {risk_color}; }}
            .risk-circle .label {{ font-size: 0.6em; color: #888; }}
            
            /* Stats Grid */
            .stats-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-bottom: 25px; }}
            .stat-card {{ background: #111118; padding: 15px; border-radius: 6px; text-align: center; border-top: 3px solid #555; }}
            .stat-val {{ font-size: 1.6em; font-weight: bold; }}
            .stat-label {{ font-size: 0.8em; color: #888; margin-top: 5px; }}
            
            /* OWASP Matrix */
            .owasp-matrix {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; margin-bottom: 25px; }}
            .owasp-cell {{ background: #111118; padding: 10px; border-radius: 6px; text-align: center; border: 1px solid #222; }}
            .owasp-cell.hit {{ border-color: #ff9800; background: #1a1510; }}
            .owasp-cell .code {{ font-size: 0.75em; color: #888; font-family: Consolas; }}
            .owasp-cell .name {{ font-size: 0.7em; color: #ccc; margin-top: 3px; }}
            .owasp-cell .count {{ font-size: 1.2em; font-weight: bold; color: #ff9800; margin-top: 5px; }}
            
            /* Findings */
            .section-title {{ color: #00e5ff; font-size: 1em; letter-spacing: 1px; font-family: Consolas; margin: 25px 0 15px; padding-bottom: 8px; border-bottom: 1px solid #222; }}
            .finding {{ background: #111118; margin-bottom: 12px; border-radius: 6px; overflow: hidden; border: 1px solid #1a1a22; }}
            .finding-header {{ padding: 12px 15px; display: flex; justify-content: space-between; align-items: center; background: #151520; }}
            .finding-header .title {{ font-weight: bold; font-family: Consolas; }}
            .finding-body {{ padding: 15px; }}
            .finding-meta {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }}
            
            .badge {{ padding: 2px 8px; border-radius: 3px; font-size: 0.75em; font-weight: bold; color: #fff; }}
            .critical {{ background: #d32f2f; }} .high {{ background: #f44336; }}
            .medium {{ background: #ff9800; color: #000; }} .low {{ background: #4caf50; }} .info {{ background: #2196f3; }}
            .badge-cvss {{ background: #000; border: 1px solid #555; color: #ff9800; }}
            .badge-cwe {{ background: #222; border: 1px solid #444; color: #ccc; }}
            .badge-owasp {{ background: #0d1b2a; border: 1px solid #2196f3; color: #2196f3; }}
            
            pre {{ background: #000; padding: 10px; overflow-x: auto; border-radius: 4px; color: #00e676; font-size: 0.85em; white-space: pre-wrap; word-wrap: break-word; }}
            
            .remediation {{ background: #0a1520; border: 1px solid #1a3040; border-radius: 4px; padding: 12px; margin-top: 10px; }}
            .remediation h4 {{ color: #2196f3; font-size: 0.85em; margin-bottom: 8px; }}
            .remediation ol {{ padding-left: 20px; font-size: 0.85em; }}
            .remediation li {{ margin-bottom: 5px; color: #ccc; }}
            .remediation pre {{ margin-top: 8px; font-size: 0.8em; }}
            
            .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #222; color: #555; font-size: 0.8em; text-align: center; }}
            
            @media print {{
                body {{ background: #fff; color: #222; }}
                .finding {{ border: 1px solid #ddd; }}
                .finding-header {{ background: #f5f5f5; }}
                pre {{ background: #f0f0f0; color: #333; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="report-header">
                <h1>LOCKON ORBITAL STRIKE — SECURITY ASSESSMENT</h1>
                <div class="meta">
                    <span>TARGET: {target}</span>
                    <span>DATE: {timestamp}</span>
                    <span>FINDINGS: {total}</span>
                </div>
            </div>

            <!-- Executive Summary -->
            <div class="exec-summary">
                <h2>EXECUTIVE SUMMARY</h2>
                <div class="risk-gauge">
                    <div class="risk-circle">
                        <div class="score">{int(risk_score)}</div>
                        <div class="label">{risk_label}</div>
                    </div>
                    <div>
                        <p style="font-size:0.95em;">The automated security assessment identified <strong>{total}</strong> findings across the target application.</p>
                        <p style="font-size:0.85em; color:#888; margin-top:5px;">
                            {stats['Critical']} Critical | {stats['High']} High | {stats['Medium']} Medium | {stats['Low']} Low | {stats['Info']} Informational
                        </p>
                    </div>
                </div>
            </div>

            <!-- Severity Stats -->
            <div class="stats-grid">
                <div class="stat-card" style="border-color: #d32f2f;"><div class="stat-val" style="color: #d32f2f;">{stats['Critical']}</div><div class="stat-label">CRITICAL</div></div>
                <div class="stat-card" style="border-color: #f44336;"><div class="stat-val" style="color: #f44336;">{stats['High']}</div><div class="stat-label">HIGH</div></div>
                <div class="stat-card" style="border-color: #ff9800;"><div class="stat-val" style="color: #ff9800;">{stats['Medium']}</div><div class="stat-label">MEDIUM</div></div>
                <div class="stat-card" style="border-color: #4caf50;"><div class="stat-val" style="color: #4caf50;">{stats['Low']}</div><div class="stat-label">LOW</div></div>
                <div class="stat-card" style="border-color: #2196f3;"><div class="stat-val" style="color: #2196f3;">{stats['Info']}</div><div class="stat-label">INFO</div></div>
            </div>

            <!-- OWASP Top 10 Coverage -->
            <div class="section-title">OWASP TOP 10 (2021) COVERAGE</div>
            <div class="owasp-matrix">
    """
    
    for code, name in owasp_categories.items():
        count = owasp_hits.get(code, 0)
        cls = "owasp-cell hit" if count > 0 else "owasp-cell"
        html_content += f'<div class="{cls}"><div class="code">{code}</div><div class="name">{name}</div><div class="count">{count}</div></div>\n'
    
    html_content += """
            </div>
            
            <div class="section-title">DETAILED FINDINGS</div>
    """
    
    if not findings:
        html_content += '<p style="text-align:center; color:#555; padding:20px;">No vulnerabilities found.</p>'
    
    for f in sorted_findings:
        severity = f.get('severity', 'Info').capitalize()
        sev_cls = severity.lower()
        cvss_score = f.get('cvss_score', 0)
        cvss_vector = f.get('cvss_vector', '')
        cwe_id = f.get('cwe', '')
        owasp_ref = f.get('owasp', '')
        
        # Badges
        meta_badges = f'<span class="badge badge-cvss">CVSS {cvss_score}</span>' if cvss_score else ''
        if cwe_id:
            meta_badges += f' <span class="badge badge-cwe">{cwe_id}</span>'
        if owasp_ref:
            meta_badges += f' <span class="badge badge-owasp">{owasp_ref}</span>'
        
        # Exploit badge
        exploit_badge = ""
        if f.get('exploit_type'):
            exploit_badge = '<span class="badge critical" style="background:#000; color:#ff5252; border:1px solid #ff5252;">EXPLOIT AVAILABLE</span>'
        
        # Remediation section
        remediation_html = ""
        rg = f.get('remediation_guide', {})
        if isinstance(rg, dict) and rg.get('fix_steps'):
            steps_html = "".join(f"<li>{step}</li>" for step in rg['fix_steps'])
            code_html = f'<pre>{rg.get("code_example", "")}</pre>' if rg.get('code_example') else ''
            refs_html = ""
            if rg.get('references'):
                refs_html = '<p style="margin-top:8px; font-size:0.8em; color:#2196f3;">' + " | ".join(f'<a href="{r}" style="color:#2196f3;">{r}</a>' for r in rg['references']) + '</p>'
            
            remediation_html = f"""
                <div class="remediation">
                    <h4>REMEDIATION</h4>
                    {'<p style="color:#ff9800; font-size:0.8em; margin-bottom:5px;">Risk: ' + rg.get('risk', '') + '</p>' if rg.get('risk') else ''}
                    <ol>{steps_html}</ol>
                    {code_html}
                    {refs_html}
                </div>
            """
        
        evidence_text = str(f.get('evidence', 'N/A')).replace('<', '&lt;').replace('>', '&gt;')
        
        html_content += f"""
            <div class="finding">
                <div class="finding-header">
                    <div>
                        <span class="title">{f.get('type')}</span>
                        {exploit_badge}
                    </div>
                    <span class="badge {sev_cls}">{severity.upper()}</span>
                </div>
                <div class="finding-body">
                    <div class="finding-meta">{meta_badges}</div>
                    <p style="color:#ccc; font-size:0.9em;">{f.get('detail')}</p>
                    <div style="margin-top:10px;"><strong style="color:#888; font-size:0.85em;">EVIDENCE:</strong></div>
                    <pre>{evidence_text}</pre>
                    {remediation_html}
                </div>
            </div>
        """

    html_content += f"""
            <div class="footer">
                Generated by LOCKON ORBITAL STRIKE | {timestamp}<br>
                {total} findings | Risk Score: {int(risk_score)}/100
            </div>
        </div>
    </body>
    </html>
    """

    if not os.path.exists("reports"):
        os.makedirs("reports")
    full_path = os.path.join("reports", filename)
    with open(full_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return full_path