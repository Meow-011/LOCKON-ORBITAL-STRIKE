import aiohttp
import asyncio
import re
import math

# Regex Patterns
SECRET_REGEX = {
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}", # AWS Validate ยากถ้าไม่มี Signature V4 แต่หาไว้ก่อน
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})"
}

def shannon_entropy(data):
    if not data: return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

async def validate_google_key(session, key):
    # Test with Google Static Maps API (Low risk, clear success/fail)
    url = f"https://maps.googleapis.com/maps/api/staticmap?center=40.714728,-73.998672&zoom=12&size=400x400&key={key}"
    try:
        async with session.get(url, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                return "Active (Google Maps API Access Confirmed)"
            elif resp.status == 403:
                return "Inactive/Restricted"
    except: pass
    return "Unknown Status"

async def validate_stripe_key(session, key):
    # Stripe keys can be checked by hitting the tokens endpoint (safe check)
    url = "https://api.stripe.com/v1/tokens"
    try:
        auth = aiohttp.BasicAuth(login=key)
        async with session.post(url, auth=auth, timeout=5, ssl=True) as resp:
            text = await resp.text()
            if "error" not in text or "Invalid API Key" not in text:
                 # ถ้า Error ไม่ใช่ Invalid Key แปลว่า Key ถูก
                 if resp.status == 200 or "param" in text: 
                     return "Active (Financial Transaction Access Possible)"
            if resp.status == 401:
                return "Invalid/Expired"
    except: pass
    return "Unknown Status"

async def validate_mailgun_key(session, key):
    # Validate via simple GET
    try:
        auth = aiohttp.BasicAuth(login='api', password=key)
        async with session.get("https://api.mailgun.net/v3/domains", auth=auth, timeout=5) as resp:
            if resp.status == 200:
                return "Active (Email Sending Access Confirmed)"
            elif resp.status == 401:
                return "Invalid"
    except: pass
    return "Unknown Status"

async def scan_js_file(session, url):
    findings = []
    try:
        async with session.get(url, timeout=10, ssl=False) as resp:
            if resp.status != 200: return []
            content = await resp.text()
            
            # 1. Regex Match
            for name, pattern in SECRET_REGEX.items():
                matches = re.findall(pattern, content)
                for secret_val in matches:
                    if len(secret_val) < 8: continue
                    
                    # [NO MERCY] Active Verification
                    status_msg = "Unverified (Regex Match Only)"
                    impact_sev = "Medium"
                    
                    if "Google" in name:
                        status_msg = await validate_google_key(session, secret_val)
                    elif "Stripe" in name:
                        status_msg = await validate_stripe_key(session, secret_val)
                    elif "Mailgun" in name:
                        status_msg = await validate_mailgun_key(session, secret_val)
                    
                    if "Active" in status_msg:
                        impact_sev = "Critical"
                        status_msg = f"🔥 {status_msg}"

                    findings.append({
                        "type": f"Secret Leak ({name})",
                        "severity": impact_sev,
                        "detail": f"Found {name} in JS file. Status: {status_msg}",
                        "evidence": f"File: {url}\nSecret: {secret_val}\nStatus: {status_msg}",
                        "remediation": "Revoke the key immediately and implement Key Rotation."
                    })
                    break 
            
            # 2. Entropy Analysis (Generic Key Hunter)
            # Find potential high-entropy strings (e.g., "ab83c7d92837f...")
            # Pattern: Alphanumeric string, length 20-64, no spaces
            potential_keys = re.findall(r'["\']([A-Za-z0-9_\-]{20,64})["\']', content)
            for key in potential_keys:
                 # Filter out common false positives (like base64 images or CSS classes)
                 if "function" in key or "return" in key or "var" in key: continue
                 
                 entropy = shannon_entropy(key)
                 if entropy > 4.5: # Threshold for random-looking strings
                     findings.append({
                        "type": "High Entropy String (Potential Secret)",
                        "severity": "Low",
                        "detail": f"Found high-entropy string ({entropy:.2f}). Could be an API Key or Token.",
                        "evidence": f"File: {url}\nString: {key}\nEntropy: {entropy:.2f}",
                        "remediation": "Review manual check if this is a hardcoded secret."
                     })

    except: pass
    return findings

async def run_secret_scan(target_url, js_urls, log_callback=None, headers=None):
    findings = []
    if not js_urls: return findings
    
    # Remove duplicates
    js_urls = list(set(js_urls))

    if log_callback: log_callback(f"🔑 Analyzed {len(js_urls)} JS files & Validating Keys (No Mercy)...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = [scan_js_file(session, url) for url in js_urls]
        results = await asyncio.gather(*tasks)
        for res in results: findings.extend(res)
            
    return findings