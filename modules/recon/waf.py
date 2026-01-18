import aiohttp
import asyncio

# ลายเซ็นของ WAF ยอดนิยม
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "__cfduid", "cf-cache-status"],
        "cookies": ["__cfduid"]
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id"],
        "server": ["awselb", "amazon"]
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "akamai-origin-hop"],
        "server": ["akamai"]
    },
    "F5 BIG-IP": {
        "cookies": ["bigipserver", "f5_cspm"],
        "server": ["big-ip"]
    },
    "Imperva Incapsula": {
        "headers": ["x-iinfo", "x-cdn", "incap-ses"],
        "cookies": ["visid_incap"]
    },
    "Sucuri": {
        "headers": ["x-sucuri-id"],
        "server": ["sucuri"]
    }
}

async def detect_waf(session, url):
    findings = []
    detected_wafs = set()
    
    try:
        async with session.get(url, timeout=10, ssl=False) as resp:
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            cookies = {k.lower(): v.value for k, v in resp.cookies.items()}
            server_header = headers.get("server", "")
            
            # วนลูปเช็ค Signature
            for waf_name, sigs in WAF_SIGNATURES.items():
                # 1. Check Headers keys
                if "headers" in sigs:
                    for h in sigs["headers"]:
                        if h in headers:
                            detected_wafs.add(waf_name)
                            
                # 2. Check Server Header value
                if "server" in sigs:
                    for s in sigs["server"]:
                        if s in server_header:
                            detected_wafs.add(waf_name)
                            
                # 3. Check Cookie keys
                if "cookies" in sigs:
                    for c in sigs["cookies"]:
                        if any(c in cookie_name for cookie_name in cookies):
                            detected_wafs.add(waf_name)
            
            if detected_wafs:
                wafs_str = ", ".join(detected_wafs)
                findings.append({
                    "type": "WAF Detected",
                    "severity": "Info",
                    "detail": f"Web Application Firewall identified: {wafs_str}",
                    "evidence": f"Signatures found in headers/cookies.",
                    "remediation": "Adjust scan speed to avoid IP ban."
                })
                
    except Exception as e:
        pass
        
    return findings

async def run_waf_scan(target_url, log_callback=None, headers=None):
    findings = []
    if log_callback: log_callback(f"🛡️ Checking for WAF/CDN protection...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        findings = await detect_waf(session, target_url)
        
    return findings