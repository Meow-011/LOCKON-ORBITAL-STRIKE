import aiohttp
import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Payloads to trigger errors
ERROR_PAYLOADS = [
    "'", "\"", "[]", "{}", "<", ">", ";", "%00", "\\",
    "{{7*7}}", "${7*7}", "a"*1000
]

# Patterns to identify sensitive info in errors
SENSITIVE_PATTERNS = {
    "SQL Syntax": r"(SQL syntax|MySQL Error|ODBC SQL Server Driver|Unclosed quotation mark)",
    "Path Disclosure": r"(\/var\/www\/|\/home\/|\/usr\/local\/|C:\\Inetpub\\|C:\\Windows\\)",
    "Stack Trace": r"(at [a-zA-Z0-9_\.]+\([a-zA-Z0-9_\.\s,:]+\)|Traceback \(most recent call last\))",
    "Framework Info": r"(Django Version|Tomcat|Powered by Jetty|Werkzeug Debugger)",
    "PHP Error": r"(Parse error|Fatal error|Warning: include)",
    # [NEW] Debug Mode Signatures
    "Laravel Ignition": r"(Ignition|Whoops, looks like something went wrong|The stream or file)",
    "Django Debug": r"(Request Method:|Request URL:|Django Version:|Using the URLconf defined in)",
    "Spring Boot Whitelabel": r"(Whitelabel Error Page|This application has no explicit mapping)",
    "Symfony Profiler": r"(Symfony Profiler|X-Debug-Token)",
}

async def check_debug_mode(session, url):
    """
    Checks for enabled debug modes and accessible profiling endpoints.
    """
    findings = []
    
    # 1. Common Debug Endpoints
    debug_paths = [
        "/_ignition/health-check", # Laravel Ignition
        "/actuator", "/actuator/env", "/actuator/metrics", # Spring Boot
        "/__debug__/rss/", # Django Debug Toolbar (sometimes)
        "/telescope", # Laravel Telescope
        "/_profiler/phpinfo" # Symfony
    ]
    
    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    
    for path in debug_paths:
        target = base_url.rstrip("/") + path
        try:
             async with session.get(target, timeout=5, ssl=False) as resp:
                 if resp.status == 200:
                     # Filter false positives
                     text = await resp.text()
                     if "login" in text.lower() or "not found" in text.lower() and resp.status == 200:
                         continue
                         
                     findings.append({
                        "type": "Debug Interface Exposure",
                        "severity": "Critical",
                        "detail": f"Accessible debug/profiling endpoint detected: {path}",
                        "evidence": f"URL: {target}\nStatus: 200 OK",
                        "remediation": "Disable debug mode and restrict access to internal tools."
                    })
        except: pass
        
    return findings

async def check_error_exposure(session, url):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    # 1. Check Debug Mode (One-time per host usually, but here per URL call is fine for simpler logic)
    debug_res = await check_debug_mode(session, url)
    findings.extend(debug_res)
    
    if not params:
        return findings

    for param_name in params:
        for payload in ERROR_PAYLOADS:
            fuzzed_params = params.copy()
            fuzzed_params[param_name] = [payload]
            target_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
            
            try:
                async with session.get(target_url, timeout=10, ssl=False) as resp:
                    text = await resp.text()
                    
                    for vuln_type, pattern in SENSITIVE_PATTERNS.items():
                        match = re.search(pattern, text, re.IGNORECASE)
                        if match:
                            # Capture a snippet around the match
                            start = max(0, match.start() - 50)
                            end = min(len(text), match.end() + 50)
                            evidence = text[start:end]
                            
                            findings.append({
                                "type": f"Sensitive Information Exposure ({vuln_type})",
                                "severity": "Medium",
                                "detail": f"Application error revealed sensitive info via '{param_name}'.",
                                "evidence": f"Payload: {payload}\n\n[ERROR SNIPPET]\n...{evidence}...",
                                "remediation": "Disable verbose error messages in production. Use custom error pages."
                            })
                            # Found one type for this param is usually enough evidence
                            break 
            except:
                pass
    return findings

async def run_error_exposure_scan(target_url, log_callback=None, headers=None):
    findings = []
    # Always run debug check even if no params
    if log_callback: log_callback(f"⚠️ Triggering Application Errors & Checking Debug Modes...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        findings = await check_error_exposure(session, target_url)
            
    return findings