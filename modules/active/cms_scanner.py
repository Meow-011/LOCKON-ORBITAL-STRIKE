import aiohttp
import asyncio

async def check_wordpress_vulns(session, base_url):
    findings = []
    
    # 1. User Enumeration (REST API)
    # Hacker มักใช้ช่องทางนี้เพื่อดูรายชื่อ User (admin) แล้วเอาไป Brute Force
    api_url = f"{base_url}/wp-json/wp/v2/users"
    try:
        async with session.get(api_url, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json()
                users = [u['name'] for u in data]
                if users:
                    findings.append({
                        "type": "WordPress User Enumeration",
                        "severity": "Medium",
                        "detail": f"Exposed users via API: {', '.join(users)}",
                        "evidence": api_url,
                        "remediation": "Disable REST API user endpoints or use a security plugin."
                    })
    except Exception: pass

    # 2. XML-RPC Enabled
    # ช่องทางนี้มักถูกใช้ยิง Brute Force หรือ DDoS
    xmlrpc_url = f"{base_url}/xmlrpc.php"
    try:
        async with session.get(xmlrpc_url, timeout=5, ssl=False) as resp:
            text = await resp.text()
            if resp.status == 405 or "XML-RPC server accepts POST requests only" in text:
                 findings.append({
                    "type": "WordPress XML-RPC Enabled",
                    "severity": "Low",
                    "detail": "XML-RPC interface is enabled. Can be used for Brute Force/DDoS.",
                    "evidence": xmlrpc_url,
                    "remediation": "Disable xmlrpc.php if not needed."
                })
    except Exception: pass
    
    # 3. Sensitive Files (Debug Log)
    debug_url = f"{base_url}/wp-content/debug.log"
    try:
        async with session.get(debug_url, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                 findings.append({
                    "type": "WordPress Debug Log Exposed",
                    "severity": "High",
                    "detail": "debug.log is publicly accessible.",
                    "evidence": debug_url,
                    "remediation": "Delete debug.log and disable WP_DEBUG_LOG."
                })
    except Exception: pass

    return findings

async def run_cms_scan(target_url, log_callback=None, headers=None):
    findings = []
    # จัดการ URL ให้จบด้วย / เสมอ
    base_url = target_url.rstrip("/")
    
    # เช็คเบื้องต้นว่าเป็น WP หรือไม่ (ดูจาก wp-login.php ก็ได้)
    # แต่เพื่อความชัวร์ เราจะยิงเช็คไปเลย (เพราะบางทีเขาซ่อน Tech Header)
    
    async with aiohttp.ClientSession(headers=headers) as session:
        # ตรวจสอบ WordPress
        is_wp = False
        try:
            async with session.get(f"{base_url}/wp-login.php", timeout=5, ssl=False) as resp:
                if resp.status == 200:
                    is_wp = True
        except Exception: pass

        if is_wp:
            if log_callback: log_callback(f"🧩 WordPress detected! Running specific CMS checks...")
            wp_findings = await check_wordpress_vulns(session, base_url)
            findings.extend(wp_findings)
        else:
            # ถ้าไม่ใช่ WP อาจจะเช็ค Joomla/Drupal ต่อในอนาคต
            pass
            
    return findings