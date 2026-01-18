import aiohttp
import asyncio

async def analyze_csp(session, url):
    findings = []
    try:
        async with session.get(url, timeout=5, ssl=False) as resp:
            csp = resp.headers.get("Content-Security-Policy", "")
            
            if not csp:
                findings.append({
                    "type": "Missing CSP Header",
                    "severity": "Low",
                    "detail": "Content-Security-Policy header is missing.",
                    "evidence": "Header not found",
                    "remediation": "Implement CSP to mitigate XSS and Data Injection attacks."
                })
                return findings
            
            # วิเคราะห์ความอ่อนแอของ CSP
            issues = []
            if "unsafe-inline" in csp:
                issues.append("'unsafe-inline' allows inline scripts (Easy XSS).")
            if "unsafe-eval" in csp:
                issues.append("'unsafe-eval' allows dynamic code execution.")
            if "script-src *" in csp or "default-src *" in csp:
                issues.append("Wildcard (*) source allows loading scripts from anywhere.")
            if "data:" in csp:
                issues.append("'data:' URI allows bypassing script restrictions.")
                
            if issues:
                findings.append({
                    "type": "Weak Content Security Policy",
                    "severity": "Medium",
                    "detail": "CSP is present but configured insecurely.",
                    "evidence": f"CSP: {csp}\n\nIssues Found:\n- " + "\n- ".join(issues),
                    "remediation": "Tighten CSP rules. Remove unsafe-inline/eval if possible."
                })
            else:
                findings.append({
                    "type": "Strong CSP Detected",
                    "severity": "Info",
                    "detail": "Content Security Policy is present and appears strong.",
                    "evidence": csp
                })

    except:
        pass
        
    return findings

async def run_csp_analyze(target_url, log_callback=None, headers=None):
    findings = []
    if log_callback: log_callback(f"🛡️ Analyzing Content Security Policy (CSP)...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        findings = await analyze_csp(session, target_url)
        
    return findings