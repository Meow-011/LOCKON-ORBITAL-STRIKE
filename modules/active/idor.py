import aiohttp
import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Pattern ที่น่าจะเป็น ID
ID_PATTERNS = [
    r'id=(\d+)', r'user_id=(\d+)', r'userid=(\d+)', r'account=(\d+)', 
    r'number=(\d+)', r'order=(\d+)', r'doc=(\d+)', r'key=(\d+)',
    r'/users/(\d+)', r'/orders/(\d+)', r'/profile/(\d+)',
    # UUID Pattern (v4)
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
]

ROLE_PARAMS = ["admin", "is_admin", "isAdmin", "role", "level", "group", "access"]

async def check_role_manipulation(session, url, original_resp_len):
    """
    Checks for Privilege Escalation via Parameter Tampering.
    """
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params: return []
    
    # Check if any param looks like a role flag
    target_params = [k for k in params.keys() if any(r in k.lower() for r in ROLE_PARAMS)]
    
    for param in target_params:
        original_val = params[param][0].lower()
        
        # Determine payload based on value type
        payloads = []
        if original_val in ["false", "0", "user", "guest"]:
            if original_val == "false": payloads = ["true", "1"]
            elif original_val == "0": payloads = ["1", "99", "admin"]
            elif original_val in ["user", "guest"]: payloads = ["admin", "administrator", "superuser", "root"]
        else:
             # Blind guess
             payloads = ["true", "1", "admin"]
             
        for pay in payloads:
            fuzzed_params = params.copy()
            fuzzed_params[param] = [pay]
            target_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
            
            try:
                async with session.get(target_url, timeout=5, ssl=False) as resp:
                    text = await resp.text()
                    
                    # Heuristic: Success indicators or significant change
                    if "admin" in text.lower() and "admin" not in url:
                         findings.append({
                            "type": "Privilege Escalation (Role Manipulation)",
                            "severity": "High",
                            "detail": f"Changing '{param}' to '{pay}' revealed admin indicators.",
                            "evidence": f"Url: {target_url}\nIndicator: 'admin' found in response.",
                            "remediation": "Validate user permissions on server-side, do not trust client parameters."
                        })
                         return findings
                    
                    # Size check (if page behaves differently)
                    if abs(len(text) - original_resp_len) > 500: # Significant change
                         findings.append({
                            "type": "Potential Role Tampering",
                            "severity": "Medium",
                            "detail": f"Response changed uniquely when setting '{param}' to '{pay}'.",
                            "evidence": f"Url: {target_url}\nSize Diff: {abs(len(text) - original_resp_len)} bytes",
                            "remediation": "Review access controls."
                        })
            except Exception: pass
            
    return findings

async def check_idor(session, url, original_cookies=None, other_uuids=None):
    findings = []
    
    # 1. Baseline Request
    try:
        async with session.get(url, cookies=original_cookies, timeout=5, ssl=False) as resp_base:
            base_text = await resp_base.text()
            base_len = len(base_text)
            base_code = resp_base.status
    except Exception: return []

    # --- 2. IDOR Checks ---
    target_id = None
    replaced_urls = []
    
    # A. Numeric IDOR
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    # Query Params
    from core.kb import kb
    import base64
    import json
    
    # [SMART IDOR] Decode User ID from JWT if available
    smart_targets = [0, 1] 
    best_token = kb.get_best_token()
    if best_token:
        try:
            parts = best_token.split(".")
            if len(parts) > 1:
                padding = '=' * (4 - len(parts[1]) % 4)
                payload_str = base64.urlsafe_b64decode(parts[1] + padding).decode('utf-8')
                payload_json = json.loads(payload_str)
                for k in ['id', 'user_id', 'sub', 'uid']:
                    if k in payload_json and str(payload_json[k]).isdigit():
                        smart_targets.append(int(payload_json[k]))
                        smart_targets.append(int(payload_json[k]) - 1) # Scan neighbor
        except Exception: pass
        
    for k, v in params.items():
        if v[0].isdigit():
            original_val = int(v[0])
            
            # 1. Standard Neighbor Attack
            new_val = str(max(1, original_val - 1))
            if new_val == str(original_val): new_val = str(original_val + 1)
            
            fuzzed_params = params.copy()
            fuzzed_params[k] = [new_val]
            replaced_urls.append(urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True))))
            
            # 2. Smart Target Attack (Try accessing Admin/Specific Users)
            for target_id in list(set(smart_targets)):
                if str(target_id) != str(original_val):
                    fuzzed_params = params.copy()
                    fuzzed_params[k] = [str(target_id)]
                    replaced_urls.append(urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True))))
            
    # Path Params (Numeric & UUID)
    for pattern in ID_PATTERNS:
        match = re.search(pattern, url)
        if match:
             val = match.group(0) # Full match "id=123" or "uuid"
             # Refined extraction depending on pattern complexity (simplified here)
             # If simple valid digit
             if val.isdigit():
                 original_val = int(val)
                 new_val = str(original_val - 1)
                 replaced_urls.append(url.replace(val, new_val))
             # If UUID and we have others to swap with
             elif len(val) > 20 and other_uuids:
                 # Find a uuid that isn't this one
                 swap_uuid = next((u for u in other_uuids if u != val and u in url), None) 
                 # Wait, 'u in url' checks if known uuid is in current url.
                 # Actual logic: Extract UUID from current URL, find DIFFERENT UUID from pool.
                 current_uuid_match = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', url)
                 if current_uuid_match:
                     curr = current_uuid_match.group(0)
                     target = next((u for u in other_uuids if u != curr), None)
                     if target:
                         replaced_urls.append(url.replace(curr, target))

    # Execute IDOR Attacks
    for r_url in replaced_urls:
        try:
            async with session.get(r_url, cookies=original_cookies, timeout=5, ssl=False) as resp_idor:
                idor_len = len(await resp_idor.read())
                idor_code = resp_idor.status
                
                if idor_code == 200:
                    text = await resp_idor.text()
                    if "not found" in text.lower() or "error" in text.lower(): continue

                    len_diff = abs(base_len - idor_len)
                    if 0 < len_diff < (base_len * 0.5):
                        findings.append({
                            "type": "Potential IDOR (Insecure Direct Object Reference)",
                            "severity": "High",
                            "detail": f"Accessing resource with modified ID returned success.",
                            "evidence": f"Original: {url}\nTarget: {r_url}\nStatus: {idor_code}",
                            "remediation": "Implement proper access control checks."
                        })
                        break # One proof is enough per URL
        except Exception: pass

    # --- 3. Role Manipulation ---
    role_findings = await check_role_manipulation(session, url, base_len)
    findings.extend(role_findings)

    # --- 4. Unauthenticated Access ---
    if original_cookies:
        try:
            async with session.get(url, cookies=None, timeout=5, ssl=False) as resp_unauth:
                if resp_unauth.status == 200 and len(await resp_unauth.read()) == base_len:
                     findings.append({
                        "type": "Broken Access Control (Publicly Accessible)",
                        "severity": "High",
                        "detail": "Resource is accessible without authentication.",
                        "evidence": f"URL: {url}\nAccess works without cookies.",
                        "remediation": "Enforce authentication middleware."
                    })
        except Exception: pass
        
    return findings

async def run_idor_scan(target_url, crawled_urls, cookies=None, log_callback=None, headers=None):
    findings = []
    # แปลง Cookie string "k=v; k2=v2" เป็น dict
    cookie_dict = {}
    if cookies:
        try:
            for pair in cookies.split(';'):
                if '=' in pair:
                    k, v = pair.strip().split('=', 1)
                    cookie_dict[k] = v
        except Exception: pass
        
    # [NEW] Pre-scan: Collect all UUIDs seen in the crawled URLs
    all_uuids = set()
    uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    for u in crawled_urls:
        found = re.findall(uuid_pattern, u)
        all_uuids.update(found)
    
    # Filter URLs that have IDs (Numeric or UUID)
    target_urls = [u for u in crawled_urls if any(x.isdigit() for x in u) or re.search(uuid_pattern, u)]
    if not target_urls: return findings

    if log_callback: log_callback(f"🆔 Testing {len(target_urls)} endpoints for IDOR & Role Tampering...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = []
        for url in target_urls[:20]: # Limit
            tasks.append(check_idor(session, url, cookie_dict, other_uuids=list(all_uuids)))
        
        results = await asyncio.gather(*tasks)
        for res in results:
            findings.extend(res)
            
    return findings