import aiohttp
import asyncio
from urllib.parse import urlparse

BACKUP_EXTENSIONS = [
    ".bak", ".old", ".swp", ".tmp", ".save", "~"
]

async def check_backup_file(session, url):
    try:
        async with session.get(url, timeout=10, ssl=False, allow_redirects=False) as resp:
            if resp.status == 200:
                c_type = resp.headers.get("Content-Type", "").lower()
                text = await resp.text()
                
                # Skip false positives (soft 404s returning HTML)
                if "text/html" in c_type and len(text) > 1000 and "<html" in text.lower():
                    return None
                
                # Check if it looks like code
                is_code = any(k in text for k in ["<?php", "def ", "import ", "package ", "public class", "var ", "const "])
                
                evidence = f"Status: 200 OK\nType: {c_type}"
                if is_code or len(text) > 0:
                    # [UNCENSORED] Show FULL Source Code
                    # แสดงเนื้อหาทั้งหมดเพื่อพิสูจน์ว่าเป็น Source Code จริงๆ
                    evidence += f"\n\n[IMPACT PROOF - FULL SOURCE CODE]\n{text}\n[END OF SOURCE CODE]"
                
                return {
                    "type": "Source Code Disclosure (Backup File)",
                    "severity": "High",
                    "detail": f"Found accessible backup file: {url}. Full source code extracted.",
                    "evidence": evidence,
                    "remediation": "Remove backup files from the public web directory immediately."
                }
    except Exception:
        pass
    return None

async def run_backup_scan(target_url, crawled_urls, log_callback=None, headers=None):
    findings = []
    if not crawled_urls: return findings

    target_files = set()
    for url in crawled_urls:
        parsed = urlparse(url)
        path = parsed.path
        if "." in path and not path.endswith((".png", ".jpg", ".css", ".svg", ".woff")):
            target_files.add(url)
            
    if not target_files: return findings

    if log_callback: log_callback(f"🗑️ Hunting for FULL source code backups on {len(target_files)} assets...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = []
        for url in target_files:
            for ext in BACKUP_EXTENSIONS:
                tasks.append(check_backup_file(session, f"{url}{ext}"))
                if "/" in url:
                    base, filename = url.rsplit("/", 1)
                    if filename:
                        tasks.append(check_backup_file(session, f"{base}/_{filename}"))

        results = await asyncio.gather(*tasks)
        for res in results:
            if res:
                findings.append(res)
                if log_callback: log_callback(f"⚠️ SOURCE CODE EXPOSED: {res['detail']}")

    return findings