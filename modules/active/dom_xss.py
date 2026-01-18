from core.browser import browser_manager, PLAYWRIGHT_AVAILABLE

DOM_PAYLOADS = [
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "';alert(1)//",
    "<svg/onload=alert(1)>"
]

async def run_dom_xss_scan(target_url, log_callback=None, headers=None):
    findings = []
    
    if not PLAYWRIGHT_AVAILABLE:
        # Silent return or warn once? We warn once in scanner init usually.
        # But here we just return emptiness to not spam.
        return findings

    # Only worth scanning if there's no path? or scanning specific params?
    # DOM XSS usually happens on the "Fragment" (#) or query params handled by client JS.
    
    # We attempt to start the browser (lazy load)
    started = await browser_manager.start()
    if not started:
        if log_callback: log_callback("⚠️ Browser Engine not available. Skipping DOM XSS Scan.")
        return findings

    if log_callback: log_callback(f"👁️ Browser: Scanning {target_url} for DOM XSS...")
    
    hits = await browser_manager.scan_dom_xss(target_url, DOM_PAYLOADS)
    
    if hits:
        for payload in hits:
             findings.append({
                "type": "DOM-Based XSS (Verified via Browser)",
                "severity": "High",
                "detail": f"Browser successfully executed alert() from payload in URL fragment.",
                "evidence": f"Payload: {payload}\nReference: {target_url}#{payload}",
                "remediation": "Validate sinks (innerHTML, document.write) and sources (location.hash)."
            })

    return findings
