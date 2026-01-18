import aiohttp
import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Payloads ที่ใช้ทดสอบการเด้ง
REDIRECT_PAYLOADS = [
    "http://evil.com",
    "//evil.com",
    "https://google.com"
]

async def check_open_redirect(session, url):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        return findings

    for param_name in params:
        for payload in REDIRECT_PAYLOADS:
            fuzzed_params = params.copy()
            fuzzed_params[param_name] = [payload]
            
            new_query = urlencode(fuzzed_params, doseq=True)
            target_url = urlunparse(parsed._replace(query=new_query))
            
            try:
                # allow_redirects=False เพื่อจับ Status Code 3xx
                async with session.get(target_url, timeout=5, ssl=False, allow_redirects=False) as resp:
                    
                    if resp.status in [301, 302, 303, 307, 308]:
                        location = resp.headers.get("Location", "")
                        
                        # ถ้า Location ปลายทางมี Payload ของเรา -> โดนแล้ว
                        if "evil.com" in location or "google.com" in location:
                            findings.append({
                                "type": "Open Redirect",
                                "severity": "Medium",
                                "detail": f"Parameter '{param_name}' redirects to arbitrary external URL.",
                                "evidence": f"Payload: {payload}\nLocation Header: {location}",
                                "remediation": "Validate the redirect URL against a whitelist."
                            })
                            return findings # เจอแล้วหยุดเลย
            except:
                pass
                
    return findings

async def run_redirect_scan(target_url, log_callback=None, headers=None):
    findings = []
    # เช็คว่ามี Parameter ให้เทสไหม
    if "?" in target_url:
        if log_callback: log_callback(f"➡️ Testing Open Redirect on parameters...")
        async with aiohttp.ClientSession(headers=headers) as session:
            findings = await check_open_redirect(session, target_url)
    
    return findings