import aiohttp
import asyncio

EVIL_HOST = "evil-lockon.com"

async def check_host_header(session, url):
    findings = []
    try:
        # 1. Basic Reflection / Redirect
        # ลองเปลี่ยน Host Header เป็นเว็บอันตราย
        async with session.get(url, headers={"Host": EVIL_HOST}, timeout=5, ssl=False, allow_redirects=False) as resp:
            text = await resp.text()
            headers = resp.headers
            
            # เช็คว่ามันสะท้อนกลับมาใน Location (Redirect) หรือ Body (Cache Poisoning) ไหม
            location = headers.get("Location", "")
            
            evidence = ""
            vuln_type = ""
            
            if EVIL_HOST in location:
                vuln_type = "Host Header Injection (Open Redirect)"
                evidence = f"Host: {EVIL_HOST}\nLocation: {location}"
                
            elif EVIL_HOST in text:
                vuln_type = "Host Header Injection (Reflected)"
                evidence = f"Host: {EVIL_HOST}\nResponse Body contains injected host."
                
            if vuln_type:
                findings.append({
                    "type": vuln_type,
                    "severity": "Medium",
                    "detail": "Server trusts user-controlled Host header.",
                    "evidence": evidence,
                    "remediation": "Validate Host header against whitelist in web server config."
                })

    except Exception: pass
    return findings

async def run_host_header_scan(target_url, log_callback=None, headers=None):
    findings = []
    if log_callback: log_callback(f"👻 Testing Host Header Injection...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        findings = await check_host_header(session, target_url)
        
    return findings