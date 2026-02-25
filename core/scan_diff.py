"""
Scan Comparison Engine
Compare two scan results to identify new, fixed, and unchanged findings.
"""
import json
import os
from datetime import datetime
from core.database import get_scan_history


def _fingerprint(finding):
    """Create a unique identifier for a finding based on type + detail."""
    ftype = finding.get('type', '').strip().lower()
    detail = finding.get('detail', '').strip().lower()
    # Normalize: remove whitespace variations
    return f"{ftype}|||{detail}"


def compare_scans(scan_id_1, scan_id_2):
    """Compare two scans and return diff results.
    
    Args:
        scan_id_1: The baseline (older) scan ID
        scan_id_2: The current (newer) scan ID
    
    Returns:
        dict with keys:
        - new: findings in scan_2 but not in scan_1 (new vulnerabilities)
        - fixed: findings in scan_1 but not in scan_2 (resolved)
        - unchanged: findings in both scans
        - stats: summary counts
        - scan_1_info: metadata about scan 1
        - scan_2_info: metadata about scan 2
    """
    # Load scan data from database
    history = get_scan_history()
    
    scan_1_data = None
    scan_2_data = None
    
    for entry in history:
        if entry.get('id') == scan_id_1 or str(entry.get('id')) == str(scan_id_1):
            scan_1_data = entry
        if entry.get('id') == scan_id_2 or str(entry.get('id')) == str(scan_id_2):
            scan_2_data = entry
    
    if not scan_1_data or not scan_2_data:
        return {"error": "One or both scans not found", "new": [], "fixed": [], "unchanged": [], "stats": {}}
    
    findings_1 = scan_1_data.get('findings', [])
    findings_2 = scan_2_data.get('findings', [])
    
    if isinstance(findings_1, str):
        try: findings_1 = json.loads(findings_1)
        except: findings_1 = []
    if isinstance(findings_2, str):
        try: findings_2 = json.loads(findings_2)
        except: findings_2 = []
    
    # Build fingerprint sets
    fp_1 = {_fingerprint(f): f for f in findings_1}
    fp_2 = {_fingerprint(f): f for f in findings_2}
    
    set_1 = set(fp_1.keys())
    set_2 = set(fp_2.keys())
    
    new_fps = set_2 - set_1
    fixed_fps = set_1 - set_2
    unchanged_fps = set_1 & set_2
    
    new = [fp_2[fp] for fp in new_fps]
    fixed = [fp_1[fp] for fp in fixed_fps]
    unchanged = [fp_2[fp] for fp in unchanged_fps]
    
    # Sort by severity weight
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    for lst in [new, fixed, unchanged]:
        lst.sort(key=lambda f: sev_order.get(f.get('severity', 'Info'), 4))
    
    return {
        "new": new,
        "fixed": fixed,
        "unchanged": unchanged,
        "stats": {
            "new_count": len(new),
            "fixed_count": len(fixed),
            "unchanged_count": len(unchanged),
            "scan_1_total": len(findings_1),
            "scan_2_total": len(findings_2),
        },
        "scan_1_info": {
            "id": scan_1_data.get('id'),
            "target": scan_1_data.get('target', ''),
            "timestamp": scan_1_data.get('timestamp', ''),
        },
        "scan_2_info": {
            "id": scan_2_data.get('id'),
            "target": scan_2_data.get('target', ''),
            "timestamp": scan_2_data.get('timestamp', ''),
        }
    }


def generate_diff_report(diff_result):
    """Generate an HTML diff report from comparison results."""
    stats = diff_result.get('stats', {})
    s1 = diff_result.get('scan_1_info', {})
    s2 = diff_result.get('scan_2_info', {})
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Scan Comparison Report</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background: #0a0a0f; color: #e0e0e0; padding: 20px; }}
.container {{ max-width: 900px; margin: 0 auto; }}
h1 {{ color: #00e5ff; font-family: Consolas; }}
.summary {{ display: flex; gap: 15px; margin: 20px 0; }}
.sum-card {{ flex: 1; padding: 15px; border-radius: 6px; text-align: center; }}
.sum-card .num {{ font-size: 2em; font-weight: bold; }}
.new {{ background: #1a0a0a; border: 1px solid #f44336; }}
.new .num {{ color: #f44336; }}
.fixed {{ background: #0a1a0a; border: 1px solid #4caf50; }}
.fixed .num {{ color: #4caf50; }}
.unchanged {{ background: #0a0a1a; border: 1px solid #555; }}
.unchanged .num {{ color: #888; }}
.section {{ margin: 20px 0; }}
.section h3 {{ font-family: Consolas; margin-bottom: 10px; }}
.item {{ padding: 8px 12px; margin: 4px 0; border-radius: 4px; display: flex; justify-content: space-between; }}
.item-new {{ background: #1a0a0a; border-left: 3px solid #f44336; }}
.item-fixed {{ background: #0a1a0a; border-left: 3px solid #4caf50; }}
.item-same {{ background: #111; border-left: 3px solid #555; }}
.badge {{ padding: 2px 6px; border-radius: 3px; font-size: 0.8em; font-weight: bold; }}
</style></head><body>
<div class="container">
<h1>SCAN COMPARISON</h1>
<p style="color:#888;">Baseline: {s1.get('target','')} ({s1.get('timestamp','')}) → Current: {s2.get('target','')} ({s2.get('timestamp','')})</p>
<div class="summary">
    <div class="sum-card new"><div class="num">{stats.get('new_count',0)}</div><div>NEW</div></div>
    <div class="sum-card fixed"><div class="num">{stats.get('fixed_count',0)}</div><div>FIXED</div></div>
    <div class="sum-card unchanged"><div class="num">{stats.get('unchanged_count',0)}</div><div>UNCHANGED</div></div>
</div>
"""
    
    sev_colors = {"Critical": "#d32f2f", "High": "#f44336", "Medium": "#ff9800", "Low": "#4caf50", "Info": "#2196f3"}
    
    def render_items(items, css_class, label):
        if not items:
            return f'<div class="section"><h3>{label} (0)</h3><p style="color:#555;">None</p></div>'
        out = f'<div class="section"><h3>{label} ({len(items)})</h3>'
        for item in items:
            sev = item.get('severity', 'Info')
            color = sev_colors.get(sev, '#888')
            out += f'<div class="item {css_class}"><span>{item.get("type","Unknown")}</span><span class="badge" style="background:{color};">{sev}</span></div>'
        out += '</div>'
        return out
    
    html += render_items(diff_result.get('new', []), 'item-new', '🔴 NEW FINDINGS')
    html += render_items(diff_result.get('fixed', []), 'item-fixed', '🟢 FIXED')
    html += render_items(diff_result.get('unchanged', []), 'item-same', '⚪ UNCHANGED')
    
    html += f"<p style='color:#555; margin-top:30px; text-align:center;'>Generated: {timestamp}</p></div></body></html>"
    
    if not os.path.exists("reports"):
        os.makedirs("reports")
    path = os.path.join("reports", f"diff_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path
