import aiohttp
import asyncio

# Methods ที่อันตรายถ้าเปิดทิ้งไว้โดยไม่ยืนยันตัวตน
DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT"]

async def check_methods(session, url):
    findings = []
    
    # 1. Check OPTIONS (ถาม Server ว่ารองรับอะไรบ้าง)
    try:
        async with session.options(url, timeout=5, ssl=False) as resp:
            allow_header = resp.headers.get("Allow", "")
            if allow_header:
                findings.append({
                    "type": "HTTP Options Allowed",
                    "severity": "Info",
                    "detail": f"Server allows methods: {allow_header}",
                    "evidence": f"Allow Header: {allow_header}"
                })
                
                # เช็คว่ามี Method อันตรายไหม
                for method in DANGEROUS_METHODS:
                    if method in allow_header:
                        findings.append({
                            "type": f"Dangerous HTTP Method ({method})",
                            "severity": "Medium",
                            "detail": f"The method {method} is allowed. This could allow unauthorized file modification or debugging.",
                            "evidence": f"Allow: {allow_header}",
                            "remediation": "Disable unnecessary HTTP methods in web server configuration."
                        })
    except: pass

    # 2. Check TRACE (XST Vulnerability)
    # TRACE จะสะท้อน Request กลับมา ถ้าสะท้อน Cookie ได้ = ขโมย Session ได้แม้มี HttpOnly
    try:
        async with session.request("TRACE", url, timeout=5, ssl=False) as resp:
            if resp.status == 200 and "TRACE /" in (await resp.text()):
                findings.append({
                    "type": "Cross-Site Tracing (XST)",
                    "severity": "Medium",
                    "detail": "TRACE method is enabled and reflects the request body.",
                    "evidence": "Server responded with 200 OK to TRACE.",
                    "remediation": "Disable TRACE method."
                })
    except: pass
    
    # 3. Check PUT (File Upload Risk)
    try:
        # ลอง PUT ไฟล์หลอกๆ
        async with session.put(f"{url}/lockon_test.txt", data="test", timeout=5, ssl=False) as resp:
            if resp.status in [200, 201, 204]:
                findings.append({
                    "type": "Insecure PUT Method",
                    "severity": "High",
                    "detail": "Server allowed uploading a file via PUT method without authentication.",
                    "evidence": f"Status: {resp.status} on {url}/lockon_test.txt",
                    "remediation": "Disable PUT method or require authentication."
                })
    except: pass

    return findings

async def run_http_method_scan(target_url, log_callback=None, headers=None):
    findings = []
    if log_callback: log_callback(f"📡 Analyzing HTTP Methods Configuration...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        findings = await check_methods(session, target_url)
        
    return findings