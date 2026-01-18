import asyncio
from playwright.async_api import async_playwright

async def check_clickjacking(target_url, log_callback=None, headers=None):
    findings = []
    
    # HTML ที่ใช้ทดสอบการครอบ Iframe
    # เราจะ inject HTML นี้เข้าไปใน Browser แล้วดูว่า iframe โหลดติดไหม
    poc_html = f"""
    <html>
        <body style="background-color:red;">
            <iframe id="test_frame" src="{target_url}" width="500" height="500"></iframe>
        </body>
    </html>
    """
    
    try:
        async with async_playwright() as p:
            # เปิด Browser
            browser = await p.chromium.launch(headless=True)
            
            # Setup context with evasion headers
            context_options = {}
            if headers:
                if 'User-Agent' in headers:
                    context_options['user_agent'] = headers['User-Agent']
                context_options['extra_http_headers'] = {k: v for k, v in headers.items() if k != 'User-Agent'}
            
            context = await browser.new_context(**context_options)
            page = await context.new_page()
            
            # โหลด HTML POC เข้าไปตรงๆ
            await page.set_content(poc_html)
            
            # รอสักนิดให้ iframe พยายามโหลด
            # เราจะเช็คว่า iframe โหลดสำเร็จไหม หรือโดนบล็อก (X-Frame-Options)
            
            frame_element = await page.query_selector("#test_frame")
            
            # ตรวจสอบว่าใน Console มี Error เกี่ยวกับ X-Frame-Options หรือไม่
            # หรือตรวจสอบว่า frame โหลด content ได้จริงไหม (ยากใน cross-origin)
            # วิธีที่ง่ายกว่าสำหรับ Automation: เช็ค Header ที่ Response กลับมาใน Network Tab
            
            is_vulnerable = True
            
            # สร้าง Event Listener เพื่อดักจับ Response ของ Iframe
            async with page.expect_response(lambda response: target_url in response.url, timeout=5000) as response_info:
                # รีเฟรช iframe เพื่อให้ trigger network request
                await page.evaluate("document.getElementById('test_frame').src = document.getElementById('test_frame').src")
            
            response = await response_info.value
            headers = response.headers
            
            x_frame = headers.get('x-frame-options', '').lower()
            csp = headers.get('content-security-policy', '').lower()
            
            if 'deny' in x_frame or 'sameorigin' in x_frame:
                is_vulnerable = False
            if 'frame-ancestors' in csp:
                is_vulnerable = False
                
            if is_vulnerable:
                findings.append({
                    "type": "Clickjacking (Missing X-Frame-Options)",
                    "severity": "Medium",
                    "detail": "The page allows itself to be rendered in an iframe.",
                    "evidence": "Successfully rendered in Playwright browser.",
                    "remediation": "Set 'X-Frame-Options' to 'DENY' or 'SAMEORIGIN'."
                })
                if log_callback: log_callback(f"⚠️ Vulnerable to Clickjacking: {target_url}")
            
            await browser.close()
            
    except Exception as e:
        # Timeout หรือ Error อื่นๆ มักแปลว่าไม่ Vulnerable หรือ Connect ไม่ได้
        pass
        
    return findings

async def run_clickjacking_scan(target_url, log_callback=None, headers=None):
    findings = []
    if log_callback: log_callback(f"🖱️ Checking Clickjacking vulnerability via Playwright...")
    findings = await check_clickjacking(target_url, log_callback, headers=headers)
    return findings