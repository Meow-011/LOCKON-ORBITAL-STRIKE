import aiohttp
import asyncio

async def check_link(session, url):
    try:
        # ใช้ Method HEAD ก่อนเพื่อความเร็ว (ถ้า Server รองรับ)
        async with session.head(url, timeout=5, ssl=False) as resp:
            if resp.status == 404:
                return url, 404
            elif resp.status >= 400:
                # ถ้า HEAD ไม่ผ่าน ลอง GET อีกทีเพื่อความชัวร์
                async with session.get(url, timeout=5, ssl=False) as get_resp:
                    if get_resp.status == 404:
                        return url, 404
    except:
        # Connection Error มักแปลว่า Domain ดับไปแล้ว (DNS Error) -> น่าสงสัย
        return url, "DNS_ERROR"
        
    return None

async def run_broken_link_scan(target_url, external_urls, log_callback=None, headers=None):
    findings = []
    
    if not external_urls:
        return findings

    if log_callback: log_callback(f"🔗 Checking {len(external_urls)} external links for hijacking risks...")
    
    # กรอง Social Media หลักๆ ที่น่าสนใจเป็นพิเศษ
    social_domains = ["facebook", "twitter", "instagram", "linkedin", "github", "gitlab", "medium"]
    
    async with aiohttp.ClientSession(headers=headers) as session:
        # แบ่งงานเป็น Batch (ทีละ 20)
        tasks = []
        for url in external_urls[:50]: # ลิมิตไว้ 50 ลิงก์เพื่อไม่ให้ช้าเกินไป
            tasks.append(check_link(session, url))
        
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res:
                url, status = res
                
                # เช็คว่าเป็น Social Media หรือไม่ (High Risk)
                is_social = any(d in url for d in social_domains)
                severity = "High" if is_social else "Low"
                
                if status == 404 or status == "DNS_ERROR":
                    findings.append({
                        "type": "Broken Link Hijacking",
                        "severity": severity,
                        "detail": f"External link returns {status}. Potential for takeover.",
                        "evidence": f"Dead Link: {url}",
                        "remediation": "Remove the link or register the domain immediately."
                    })
                    if log_callback: log_callback(f"⚠️ Dead Link Found: {url}")

    return findings