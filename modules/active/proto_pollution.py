import asyncio
from playwright.async_api import async_playwright

async def check_proto_pollution(target_url, log_callback=None, headers=None):
    findings = []
    
    # Payload: พยายามยัด Property 'polluted' เข้าไปใน Object.prototype
    # ผ่านทาง URL Query Param (ท่ามาตรฐาน)
    target_with_payload = target_url
    if "?" in target_url:
        target_with_payload += "&__proto__[polluted]=true"
    else:
        target_with_payload += "?__proto__[polluted]=true"
        
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            
            # Evasion Context
            context_options = {}
            if headers:
                ua = headers.get("User-Agent", "Mozilla/5.0")
                other_headers = {k: v for k, v in headers.items() if k.lower() != "user-agent"}
                context_options["user_agent"] = ua
                context_options["extra_http_headers"] = other_headers
                
            context = await browser.new_context(**context_options)
            page = await context.new_page()
            
            # โหลดหน้าเว็บพร้อม Payload
            await page.goto(target_with_payload, timeout=15000, wait_until="domcontentloaded")
            
            # ตรวจสอบว่า window object ติดเชื้อหรือไม่
            is_polluted = await page.evaluate("() => { return window.polluted === true || ({}).polluted === true }")
            
            if is_polluted:
                findings.append({
                    "type": "Client-Side Prototype Pollution",
                    "severity": "High",
                    "detail": "Successfully injected property into Object.prototype via URL.",
                    "evidence": f"Payload: {target_with_payload}\nCheck: window.polluted === true",
                    "remediation": "Validate input keys (block __proto__, constructor, prototype) or use Object.freeze()."
                })
                if log_callback: log_callback(f"⚠️ Prototype Pollution Confirmed on {target_url}")
                
            await browser.close()
            
    except Exception as e:
        pass
        
    return findings

async def run_proto_pollution_scan(target_url, log_callback=None, headers=None):
    findings = []
    if log_callback: log_callback(f"🧬 Testing for Client-Side Prototype Pollution...")
    findings = await check_proto_pollution(target_url, log_callback, headers=headers)
    return findings