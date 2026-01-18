import aiohttp
import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode

# --- PAYLOADS ---
BOLA_IDS = [1, 2, 100, 1000, 0, -1, "admin", "test"] # Common IDs to fuzz
MASS_ASSIGNMENT_VARS = {
    # Flat
    "is_admin": True, 
    "role": "admin", 
    "isAdmin": True, 
    "access_level": 100,
    "user_role": "superadmin",
    # Nested (will be constructed dynamically)
    "user": {"role": "admin", "is_admin": True},
    "data": {"role": "admin", "isAdmin": True},
    "attributes": {"role": "admin"}
}

# ... (Previous Code) ...

async def check_mass_assignment(session, url, method):
    """
    Checks for Mass Assignment by injecting admin-related fields in JSON/POST body.
    Supports Nested JSON structures.
    """
    findings = []
    if method not in ["POST", "PUT", "PATCH"]: return []
    
    # Flatten checks + Nested checks
    for key, val in MASS_ASSIGNMENT_VARS.items():
        payload = {key: val}
        
        # Construct Nested Payload Logic (simplified)
        # If val is dict, it's already nested. If not, simple flat injection.
        # We try both injecting as top-level and wrapping in common objects.
        
        try:
            async with session.request(method, url, json=payload, timeout=5, ssl=False) as resp:
                text = await resp.text()
                # If fields reflected or success
                # Success Logic: 200/201
                if resp.status in [200, 201]:
                     # Check if parameter is reflected in response (Strong indicator)
                     # For nested: check if "admin" appears if we sent it
                     if str(val) in text or (isinstance(val, dict) and "admin" in text):
                         findings.append({
                            "type": "Potential API Mass Assignment",
                            "severity": "Medium",
                            "detail": f"API accepted elevated parameter '{key}'. Check if it persists.",
                            "evidence": f"Payload: {payload}\nResponse: {text[:200]}...",
                            "category": "API Security"
                        })
        except: pass
        
    return findings

async def check_method_fuzzing(session, url):
    """
    Checks if API allows unexpected HTTP methods (HTTP Verb Tampering).
    Includes X-HTTP-Method-Override support.
    """
    findings = []
    # 1. Dangerous Methods
    unsafe_methods = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]
    # 2. Auth Bypass Methods
    bypass_methods = ["HEAD"] 
    
    # A. Check Unsafe Methods
    for method in unsafe_methods:
        try:
            async with session.request(method, url, timeout=5, ssl=False) as resp:
                # 200/201/204 means operation success (Dangerous!)
                if resp.status in [200, 201, 204]:
                    findings.append({
                        "type": f"Unsafe HTTP Method Allowed ({method})",
                        "severity": "Medium",
                        "detail": f"Endpoint {url} accepted {method} request unexpectedly.",
                        "evidence": f"Method: {method}\nStatus: {resp.status}\nResponse: {await resp.text()[:100]}",
                        "category": "API Security"
                    })
        except: pass

    # B. Auth Bypass (HEAD)
    # Compare HEAD response code with GET/POST response code
    # If GET returns 401/403 but HEAD returns 200, it's a bypass.
    try:
        async with session.head(url, timeout=5, ssl=False) as resp_head:
            if resp_head.status == 200:
                 # Need baseline to compare? Assumed context checks elsewhere.
                 # Generally, HEAD 200 on restricted endpoint is suspicious if content logic triggers
                 pass
    except: pass
    
    # C. X-HTTP-Method-Override
    # Try sending GET/POST with Override header to simulate PUT/DELETE
    override_headers = {"X-HTTP-Method-Override": "PUT"}
    try:
        async with session.post(url, headers=override_headers, timeout=5, ssl=False) as resp:
            if resp.status in [200, 201, 204]:
                 findings.append({
                        "type": "HTTP Verb Tampering (Method Override)",
                        "severity": "High",
                        "detail": "Server supports 'X-HTTP-Method-Override' to bypass method restrictions.",
                        "evidence": f"Header: X-HTTP-Method-Override: PUT\nStatus: {resp.status}",
                        "category": "API Security"
                    })
    except: pass

    return findings

async def run_api_scan(target_url, log_callback=None, headers=None):
    findings = []
    
    # Heuristic: Only scan likely API endpoints or numeric paths
    is_api = "api" in target_url or "/v1/" in target_url or ".json" in target_url
    has_id = re.search(r'/\d+(/|$)', target_url)
    
    if not (is_api or has_id): return []

    if log_callback: log_callback(f"🔌 Fuzzing API Endpoints (BOLA, Mass Assignment)...")

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            # Baseline
            try:
                async with session.get(target_url, timeout=5, ssl=False) as base:
                    base_len = len(await base.text())
            except:
                return []

            # 1. BOLA Check (IDOR)
            if has_id:
                bola_res = await check_bola(session, target_url, base_len)
                findings.extend(bola_res)
            
            # 2. Mass Assignment (Blind guess on POST/PUT)
            ma_res = await check_mass_assignment(session, target_url, "POST")
            findings.extend(ma_res)
            ma_res_put = await check_mass_assignment(session, target_url, "PUT")
            findings.extend(ma_res_put)
            
            # 3. GraphQL
            gql_res = await check_graphql(session, target_url)
            findings.extend(gql_res)
            
            # 4. Method Fuzzing
            method_res = await check_method_fuzzing(session, target_url)
            findings.extend(method_res)

    except Exception as e:
        if log_callback: log_callback(f"[-] API Scan Error: {e}")
        
    return findings