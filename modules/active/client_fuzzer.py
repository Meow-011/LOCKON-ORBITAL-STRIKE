import aiohttp
import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Prototype Pollution Payloads
PROTO_PAYLOADS = [
    "__proto__[polluted]=true",
    "constructor[prototype][polluted]=true",
    "__proto__.polluted=true"
]

async def check_prototype_pollution(session, url):
    """
    Checks for Reflected Prototype Pollution.
    Since we don't have a JS Engine, we check if the inputs are reflected 
    into a context that LOOKS like it's being assigned or parsed securely.
    """
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params: return findings

    for param_name in params:
        for payload in PROTO_PAYLOADS:
            fuzzed_params = params.copy()
            fuzzed_params[param_name] = [payload]
            target_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
            
            try:
                async with session.get(target_url, timeout=5, ssl=False) as resp:
                    text = await resp.text()
                    
                    # Detection logic:
                    # If we see our payload reflected verbatim in a <script> tag or inside a JSON object,
                    # AND it's not properly escaped, it might be dangerous.
                    
                    # 1. Check Reflection
                    if "polluted" in text:
                        # 2. Check Context (Simple Heuristic)
                        # If it appears inside a script block or existing JS object structure
                        # This is very prone to FP without a browser, so we mark as "Potential"
                        if "<script>" in text or "var " in text or "{" in text:
                             findings.append({
                                "type": "Potential Prototype Pollution (Reflected)",
                                "severity": "Medium",
                                "detail": f"Parameter '{param_name}' allows injection of prototype properties.",
                                "evidence": f"Payload: {payload}\nReflected in response.",
                                "remediation": "Validate inputs and freeze Object.prototype."
                             })
                             break # Found one payload working
            except: pass
            
    return findings

async def check_postmessage(session, url, text):
    """
    Static Analysis of JS files for Insecure PostMessage.
    """
    findings = []
    
    # 1. Find Event Listener
    if "addEventListener" in text and '"message"' in text:
        # 2. Check for Origin Validation (Loose check)
        # If we see "message" listener but NO "origin" check or "postMessage('*')"
        
        # Check source code snippet around the listener? Too complex for regex.
        # We look for dangerous patterns globally in the file.
        
        if "event.origin" not in text and "evt.origin" not in text and "e.origin" not in text:
             findings.append({
                "type": "Insecure PostMessage Listener (Missing Origin Check)",
                "severity": "High",
                "detail": f"JavaScript at {url} listens for messages but does not seem to validate origin.",
                "evidence": "Found 'addEventListener(\"message\")' without 'event.origin' check.",
                "remediation": "Always verify event.origin before processing data."
            })
            
    # Check for sending to wildcard
    if "postMessage('*')" in text or 'postMessage("*")' in text:
        findings.append({
            "type": "Insecure PostMessage Sender (Wildcard Target)",
            "severity": "Medium",
            "detail": f"JavaScript at {url} sends messages to any origin (*).",
            "evidence": "Found 'postMessage(\"*\")'.",
            "remediation": "Specify the exact target origin instead of '*'."
        })
        
    return findings

async def run_client_deep_scan(target_url, log_callback=None, headers=None):
    findings = []
    
    if "?" in target_url:
        # 1. Prototype Pollution
        async with aiohttp.ClientSession(headers=headers) as session:
            pp_res = await check_prototype_pollution(session, target_url)
            findings.extend(pp_res)
            
    # 2. PostMessage (Scan JS files)
    # This usually requires crawling JS files first. 
    # If target_url IS a JS file:
    if target_url.endswith(".js"):
        async with aiohttp.ClientSession(headers=headers) as session:
            try:
                async with session.get(target_url, timeout=5, ssl=False) as resp:
                    text = await resp.text()
                    pm_res = await check_postmessage(session, target_url, text)
                    findings.extend(pm_res)
            except: pass
            
    return findings
