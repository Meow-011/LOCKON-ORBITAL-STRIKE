import aiohttp
import asyncio
import json

# Keys often associated with admin privileges
# If injected and accepted, can lead to Privilege Escalation
PRIVESC_KEYS = [
    {"role": "admin"},
    {"role": "administrator"},
    {"is_admin": True},
    {"isAdmin": True},
    {"permissions": "all"},
    {"groups": ["admin"]},
    {"level": 99},
    {"plan": "premium"},
    {"subscription": "pro"}
]

async def check_mass_assignment(session, url, method="POST", original_json=None):
    findings = []
    
    # Needs base JSON to inject into
    if not original_json or not isinstance(original_json, dict):
        return findings
        
    for payload_dict in PRIVESC_KEYS:
        # Inject the key
        modified_json = original_json.copy()
        for k, v in payload_dict.items():
            modified_json[k] = v
            
        try:
            # We assume the user creates/updates something (POST/PUT/PATCH)
            async with session.request(method, url, json=modified_json, timeout=5, ssl=False) as resp:
                text = await resp.text()
                
                # Detection:
                # 1. Reflection: The response JSON contains the injected key/value
                # 2. Status: Success (200/201)
                
                if resp.status in [200, 201]:
                    try:
                        resp_json = json.loads(text)
                        for k, v in payload_dict.items():
                            # Check if injected key is present in response AND matches value
                            if k in resp_json and resp_json[k] == v:
                                # High Confidence of Mass Assignment
                                findings.append({
                                    "type": "Mass Assignment (Privilege Escalation)",
                                    "severity": "Critical",
                                    "detail": f"Endpoint accepted and reflected injected privilege key: '{k}': {v}",
                                    "evidence": f"Payload: {payload_dict}\nResponse: {text[:200]}...",
                                    "remediation": "Whitelist allowed parameters (DTOs) and reject unknown fields."
                                })
                    except ValueError:
                        pass
        except Exception:
            pass
            
    return findings

async def run_privesc_scan(target_url, log_callback=None, headers=None, method="POST", body="{}"):
    # This usually runs on API endpoints discovered with JSON bodies.
    # For now, we test if we can parse the body.
    try:
        if isinstance(body, str):
            json_body = json.loads(body)
        else:
            json_body = body
    except Exception:
        return [] # Not JSON
        
    async with aiohttp.ClientSession(headers=headers) as session:
        return await check_mass_assignment(session, target_url, method, json_body)
