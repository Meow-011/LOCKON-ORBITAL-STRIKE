import aiohttp
import asyncio

async def check_security_headers(session, url):
    """ ตรวจสอบ HTTP Security Headers ที่หายไป """
    findings = []
    try:
        async with session.get(url, timeout=10, ssl=False) as response:
            headers = response.headers
            
            # รายการ Header ที่ควรมี
            security_headers = {
                "X-Frame-Options": "Prevent Clickjacking attacks.",
                "X-Content-Type-Options": "Prevent MIME-sniffing.",
                "Strict-Transport-Security": "Enforce HTTPS (HSTS).",
                "Content-Security-Policy": "Mitigate XSS and Data Injection."
            }
            
            for header, desc in security_headers.items():
                if header not in headers:
                    findings.append({
                        "type": "Missing Header",
                        "severity": "Low",
                        "detail": f"Missing '{header}' header.",
                        "remediation": desc
                    })
                    
            # เช็ค Server Info Leakage
            if "Server" in headers:
                findings.append({
                    "type": "Info Disclosure",
                    "severity": "Low",
                    "detail": f"Server header exposed: {headers['Server']}",
                    "remediation": "Hide server version to prevent fingerprinting."
                })
                
    except Exception as e:
        # เงียบไว้ถ้าต่อไม่ได้ (เดี๋ยว scanner หลักจะจัดการ error ใหญ่เอง)
        pass
        
    return findings

async def check_sensitive_files(session, base_url):
    """ ตรวจสอบไฟล์ที่มักเผลอเปิดทิ้งไว้ """
    findings = []
    files_to_check = [
        ".env", "config.php.bak", ".git/HEAD", "robots.txt", "sitemap.xml",
        # Cloud Metadata / Credentials
        ".aws/credentials", ".aws/config",
        ".gcp/credentials.db", 
        ".azure/credentials",
        "cloud-config.yml"
    ]
    
    for file in files_to_check:
        target = f"{base_url.rstrip('/')}/{file}"
        try:
            async with session.get(target, timeout=5, ssl=False) as resp:
                if resp.status == 200:
                    severity = "High" if ".env" in file or ".git" in file else "Info"
                    findings.append({
                        "type": "Sensitive File Exposure",
                        "severity": severity,
                        "detail": f"Found accessible file: {file}",
                        "remediation": "Ensure this file is not publicly accessible."
                    })
        except:
            pass
            
    return findings

async def run_auth_security_scan(target_url, log_callback=None, headers=None):
    """ Main Function สำหรับ Auth/Security Scan """
    findings = []
    if log_callback: log_callback("   Running Header & File Analysis...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        # Check Headers and Files Concurrently for Speed
        results = await asyncio.gather(
            check_security_headers(session, target_url),
            check_sensitive_files(session, target_url)
        )
        
        for r in results:
            findings.extend(r)
        
    return findings