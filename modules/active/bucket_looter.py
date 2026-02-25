import aiohttp
import asyncio
import re
from urllib.parse import urlparse

# Regex สำหรับจับ URL ของ Cloud Storage ค่ายดัง
BUCKET_PATTERNS = {
    "AWS S3": r'[a-z0-9\.\-]+\.s3\.amazonaws\.com',
    "Google Cloud": r'storage\.googleapis\.com\/[a-z0-9\.\-_]+',
    "Azure Blob": r'[a-z0-9]+\.blob\.core\.windows\.net'
}

async def check_bucket_permissions(session, bucket_url):
    try:
        # เติม https:// ถ้าไม่มี
        target = f"https://{bucket_url}" if not bucket_url.startswith("http") else bucket_url
        
        # ลอง GET ดู (ถ้า Public มักจะคืน XML รายชื่อไฟล์มาให้)
        async with session.get(target, timeout=5, ssl=False) as resp:
            text = await resp.text()
            
            # เช็คว่า List ไฟล์ได้ไหม (เจอ XML Tag ของ S3/GCP)
            if "ListBucketResult" in text or "<Contents>" in text or "<Blob>" in text:
                # [NO MERCY] Extract Filenames
                # พยายามดึงชื่อไฟล์ออกมาสัก 5 ไฟล์เพื่อเป็นหลักฐาน
                files = re.findall(r'<Key>(.*?)</Key>', text)
                if not files: files = re.findall(r'<Name>(.*?)</Name>', text) # Azure/GCP variants
                
                preview_files = "\n".join(files[:5])
                total_files = len(files)
                
                return {
                    "type": "Public Cloud Bucket (Data Leak)",
                    "severity": "Critical",
                    "detail": f"Cloud storage '{bucket_url}' allows public listing of files.",
                    "evidence": f"Bucket URL: {target}\n\n[LOOT PREVIEW - TOTAL {total_files} FILES]\n{preview_files}\n...(truncated)",
                    "remediation": "Disable 'Public Access' and list permissions on the bucket."
                }
            elif "AccessDenied" in text or "AuthenticationFailed" in text:
                return {
                    "type": "Cloud Bucket Detected (Protected)",
                    "severity": "Info",
                    "detail": f"Found bucket '{bucket_url}' but access is denied.",
                    "evidence": f"Bucket: {target}",
                    "remediation": "Ensure this bucket is intended to be exposed publicly."
                }
    except Exception: pass
    return None

async def run_bucket_looter(target_url, crawled_urls, log_callback=None, headers=None):
    findings = []
    potential_buckets = set()
    
    # 1. Scan Source Codes for patterns
    # เราจะสแกนหน้าเว็บที่ Crawl มาได้ เพื่อหาลิงก์ที่ชี้ไป Cloud
    urls_to_scan = crawled_urls[:20] + [target_url] # สุ่มตรวจ 20 หน้าแรก + หน้าหลัก
    
    if log_callback: log_callback(f"☁️ Hunting for exposed Cloud Buckets in {len(urls_to_scan)} pages...")

    async with aiohttp.ClientSession(headers=headers) as session:
        for url in urls_to_scan:
            try:
                async with session.get(url, timeout=5, ssl=False) as resp:
                    text = await resp.text()
                    for provider, pattern in BUCKET_PATTERNS.items():
                        matches = re.findall(pattern, text)
                        for m in matches:
                            # Clean up match
                            m = m.strip("'\"")
                            potential_buckets.add(m)
            except Exception: pass
            
        if not potential_buckets: return findings

        if log_callback: log_callback(f"   Found {len(potential_buckets)} potential buckets. Checking permissions...")

        # 2. Check Permissions (Active)
        tasks = [check_bucket_permissions(session, bucket) for bucket in potential_buckets]
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res: findings.append(res)
            
    return findings