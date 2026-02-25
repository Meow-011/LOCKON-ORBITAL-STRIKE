import aiohttp
import asyncio
import re

# Wordlist
COMMON_PATHS = [
    ".env", ".git/HEAD", ".vscode/settings.json", ".ds_store",
    "admin/", "administrator/", "login/", "dashboard/",
    "config.php", "wp-config.php.bak", "wp-config.php.old",
    "backup.zip", "database.sql", "dump.sql", "www.zip",
    "robots.txt", "sitemap.xml", "phpinfo.php",
    "server-status", ".htaccess"
]

async def check_path(session, url):
    try:
        # [CRITICAL] allow_redirects=False เพื่อป้องกันการเด้งไปหน้า Login/Home
        async with session.get(url, timeout=10, ssl=False, allow_redirects=False) as resp:
            
            if resp.status == 200:
                # อ่านแบบ Binary ก่อนเผื่อเจอไฟล์ Binary (zip, ds_store)
                content_bytes = await resp.read()
                
                # พยายาม decode เป็น text (ถ้าทำได้)
                try:
                    text = content_bytes.decode('utf-8', errors='ignore')
                except Exception:
                    text = ""

                content_type = resp.headers.get("Content-Type", "").lower()
                is_html = "<html" in text.lower() or "<body" in text.lower() or "<!doctype" in text.lower()
                
                # --- 1. ตรวจสอบ .env (ต้องเป็น Plain Text Key=Value) ---
                if url.endswith(".env"):
                    # ถ้าเนื้อหาเป็น HTML หรือไม่มีเครื่องหมาย = แสดงว่าปลอม (Soft 404)
                    if is_html or "=" not in text:
                        return None
                    
                    # ถ้าผ่านเงื่อนไข ให้ดูดหมดเปลือก
                    return {
                        "type": "Critical Configuration File (.env)",
                        "severity": "Critical",
                        "detail": f"Environment variables exposed at {url}",
                        "evidence": f"[IMPACT PROOF - FULL DUMP]\n{text[:5000]}" # Limit 5000 chars
                    }

                # --- 2. ตรวจสอบ JSON (settings.json) ---
                if url.endswith(".json"):
                    if is_html: return None
                    if not (text.strip().startswith("{") or text.strip().startswith("[")):
                        return None
                        
                    return {
                        "type": "Sensitive Config Exposure (JSON)",
                        "severity": "High",
                        "detail": f"Configuration file exposed: {url}",
                        "evidence": text[:2000]
                    }

                # --- 3. ตรวจสอบ Git Head ---
                if url.endswith(".git/HEAD"):
                    if "ref: refs/" in text:
                        return {
                            "type": "Git Repository Exposure",
                            "severity": "Critical",
                            "detail": "Source code version control exposed (.git)",
                            "evidence": text
                        }
                    return None

                # --- 4. ตรวจสอบ Source Code Backup (.bak, .old) ---
                # ถ้ามัน execute php ไม่ได้ Server มักจะส่ง plain text มา
                if any(url.endswith(ext) for ext in [".bak", ".old", ".swp", ".txt"]):
                    if is_html: return None # ถ้าเป็นหน้า error page ข้ามไป
                    
                    # เช็ค Signature ของ Code
                    if "<?php" in text or "def " in text or "import " in text or "public class" in text:
                        return {
                            "type": "Source Code Disclosure",
                            "severity": "Critical",
                            "detail": f"Backup file contains raw source code: {url}",
                            "evidence": f"[SOURCE CODE DUMP]\n{text[:3000]}"
                        }

                # --- 5. ตรวจสอบ Binary / Archive (.zip, .sql, .ds_store) ---
                if url.endswith((".zip", ".sql", ".ds_store", ".tar.gz")):
                    if is_html: return None # ถ้าโหลดมาแล้วเป็น HTML แสดงว่าปลอม
                    
                    # ถ้า Content-Type ถูกต้อง หรือเป็น Binary stream
                    if len(content_bytes) > 100:
                        preview = f"Binary File: {len(content_bytes)} bytes"
                        if url.endswith(".sql"):
                            preview = text[:1000] # SQL อ่านเป็น text ได้
                            
                        return {
                            "type": "Sensitive Backup/Database File",
                            "severity": "Critical",
                            "detail": f"Downloadable backup found: {url}",
                            "evidence": preview
                        }

                # --- 6. General Interesting Files (phpinfo, server-status) ---
                if "phpinfo" in url and "PHP Version" in text:
                    return {"type": "Info Disclosure (phpinfo)", "severity": "Medium", "detail": "PHP Info page found", "evidence": "PHP Version detected"}
                
                if "server-status" in url and "Apache Server Status" in text:
                    return {"type": "Server Status Exposure", "severity": "Medium", "detail": "Apache server-status is public", "evidence": "Apache Status Page"}

            elif resp.status == 403:
                # 403 ก็ยังน่าสนใจ เพราะแปลว่าไฟล์มีอยู่จริงแต่ติด Permission
                return {
                    "type": "Forbidden Resource (Potential Target)",
                    "severity": "Info",
                    "detail": f"Path exists but is forbidden: {url}",
                    "evidence": "Status: 403 Forbidden"
                }
    except Exception:
        pass
    return None

async def run_directory_scan(target_url, log_callback=None, headers=None):
    findings = []
    base_url = target_url.rstrip("/") + "/"
    
    if log_callback: log_callback(f"🕵️‍♂️ Smart Brute-forcing & Validating Secrets...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = []
        for path in COMMON_PATHS:
            full_url = base_url + path
            tasks.append(check_path(session, full_url))
        
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res:
                findings.append(res)
                if log_callback and res['severity'] in ['Critical', 'High']:
                     log_callback(f"🔥 CRITICAL: {res['detail']}")
                     
    return findings