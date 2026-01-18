import os
import json
from datetime import datetime

def generate_html_report(target, findings):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = f.get('severity', 'Info')
        if sev in stats: stats[sev] += 1
        else: stats["Info"] += 1

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>LOCKON Report - {target}</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; background-color: #121212; color: #e0e0e0; margin: 0; padding: 20px; }}
            .container {{ max-width: 1000px; margin: 0 auto; }}
            .header {{ border-bottom: 2px solid #333; padding-bottom: 10px; margin-bottom: 20px; }}
            h1 {{ color: #ff5252; margin: 0; }}
            .meta {{ color: #888; font-size: 0.9em; margin-top: 5px; }}
            
            .stats-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-bottom: 30px; }}
            .stat-card {{ background: #1e1e1e; padding: 15px; border-radius: 5px; text-align: center; border-top: 3px solid #555; }}
            .stat-val {{ font-size: 1.5em; font-weight: bold; }}
            
            .finding {{ background: #1e1e1e; margin-bottom: 15px; border-radius: 5px; overflow: hidden; }}
            .finding-header {{ padding: 10px 15px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; }}
            .finding-body {{ padding: 15px; border-top: 1px solid #333; display: block; }}
            
            .badge {{ padding: 3px 8px; border-radius: 3px; font-size: 0.8em; font-weight: bold; color: #fff; }}
            .critical {{ background: #d32f2f; }} .high {{ background: #f44336; }}
            .medium {{ background: #ff9800; }} .low {{ background: #4caf50; }} .info {{ background: #2196f3; }}
            
            pre {{ background: #000; padding: 10px; overflow-x: auto; border-radius: 3px; color: #00e676; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>LOCKON SECURITY REPORT</h1>
                <div class="meta">Target: {target} | Date: {timestamp}</div>
            </div>

            <div class="stats-grid">
                <div class="stat-card" style="border-color: #d32f2f;"><div class="stat-val" style="color: #d32f2f;">{stats['Critical']}</div><div>CRITICAL</div></div>
                <div class="stat-card" style="border-color: #f44336;"><div class="stat-val" style="color: #f44336;">{stats['High']}</div><div>HIGH</div></div>
                <div class="stat-card" style="border-color: #ff9800;"><div class="stat-val" style="color: #ff9800;">{stats['Medium']}</div><div>MEDIUM</div></div>
                <div class="stat-card" style="border-color: #4caf50;"><div class="stat-val" style="color: #4caf50;">{stats['Low']}</div><div>LOW</div></div>
                <div class="stat-card" style="border-color: #2196f3;"><div class="stat-val" style="color: #2196f3;">{stats['Info']}</div><div>INFO</div></div>
            </div>

            <h2>Findings Details</h2>
            {'<p style="text-align:center; color:#555;">No vulnerabilities found.</p>' if not findings else ''}
    """
    
    for f in findings:
        severity = f.get('severity', 'Info').capitalize()
        sev_cls = severity.lower()
        
        # [NEW] Check for Exploit
        exploit_badge = ""
        if f.get('exploit_type'):
            exploit_badge = '<span class="badge critical" style="background:#000; color:#ff5252; border:1px solid #ff5252;">🔥 EXPLOIT AVAILABLE</span>'
        
        html_content += f"""
            <div class="finding">
                <div class="finding-header" style="background: #252525;">
                    <div>
                        <span style="font-weight:bold;">{f.get('type')}</span>
                        {exploit_badge}
                    </div>
                    <span class="badge {sev_cls}">{severity.upper()}</span>
                </div>
                <div class="finding-body">
                    <p style="color:#ccc;">{f.get('detail')}</p>
                    <div style="margin-top:10px;"><strong>Evidence:</strong></div>
                    <pre>{str(f.get('evidence', 'N/A')).replace('<', '&lt;')}</pre>
                    <div style="margin-top:10px; font-size:0.9em; color:#aaa;">
                        <strong>Remediation:</strong> {f.get('remediation', 'N/A')}
                    </div>
                </div>
            </div>
        """

    html_content += "</div></body></html>"

    if not os.path.exists("reports"):
        os.makedirs("reports")
    full_path = os.path.join("reports", filename)
    with open(full_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return full_path