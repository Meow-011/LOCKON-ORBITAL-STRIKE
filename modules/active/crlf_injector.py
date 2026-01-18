import aiohttp
import asyncio
from urllib.parse import urlparse, quote

# Payloads: พยายามฉีด Header ใหม่เข้าไป
# %0d%0a = \r\n (New Line)
CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:InjectedCookie=LockonWasHere",
    "%0d%0aX-Injected-Header:Lockon"
]

async def check_crlf(session, url):
    findings = []
    parsed = urlparse(url)
    path = parsed.path
    
    # 1. Path Injection
    # ลองฉีดใส่ Path: /index.php%0d%0aSet-Cookie:...
    for payload in CRLF_PAYLOADS:
        target_url = f"{parsed.scheme}://{parsed.netloc}{path}{payload}"
        try:
            async with session.get(target_url, timeout=5, ssl=False) as resp:
                # เช็คว่า Header ที่เราฉีด มันโผล่มาใน Response Headers จริงไหม
                headers = resp.headers
                
                is_vuln = False
                if "InjectedCookie" in str(headers) or "LockonWasHere" in str(headers):
                    is_vuln = True
                if "X-Injected-Header" in headers or "Lockon" in str(headers):
                    is_vuln = True
                    
                if is_vuln:
                    findings.append({
                        "type": "CRLF Injection (HTTP Response Splitting)",
                        "severity": "High",
                        "detail": "Successfully injected arbitrary HTTP headers via URL path.",
                        "evidence": f"Payload: {payload}\nInjected Header Found in Response.",
                        "remediation": "Remove CRLF characters from input before using them in HTTP headers."
                    })
                    return findings
        except: pass
        
    return findings

async def run_crlf_scan(target_url, log_callback=None, headers=None):
    findings = []
    if log_callback: log_callback(f"🏁 Testing CRLF Injection / HTTP Response Splitting...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        findings = await check_crlf(session, target_url)
        
    return findings