import aiohttp
import asyncio

async def check_cors(session, url):
    findings = []
    
    # Origin ที่เราจะใช้ทดสอบ (จำลองว่าเป็นเว็บ Hacker)
    evil_origin = "http://evil-lockon.com"
    
    headers = {
        "Origin": evil_origin
    }
    
    try:
        async with session.get(url, headers=headers, timeout=5, ssl=False) as resp:
            # อ่าน Header ที่ตอบกลับมา
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            
            # เงื่อนไขการเกิดช่องโหว่:
            # 1. Server สะท้อน Origin ของเรากลับมา (หรือเป็น *)
            # 2. Server ยอมรับ Credentials (Cookies/Auth headers) -> อันนี้อันตรายสุด
            
            if evil_origin in acao and "true" in acac.lower():
                findings.append({
                    "type": "CORS Misconfiguration (Critical)",
                    "severity": "High",
                    "detail": f"Server allows arbitrary origin '{evil_origin}' with credentials.",
                    "evidence": f"ACAO: {acao}\nACAC: {acac}",
                    "remediation": "Validate 'Origin' header against a whitelist. Do not reflect the input."
                })
            elif acao == "*" and "true" not in acac.lower():
                findings.append({
                    "type": "CORS Wildcard (Relaxed)",
                    "severity": "Low",
                    "detail": "Server allows access from any origin (*).",
                    "remediation": "This is okay for public APIs, but risky for private data."
                })
                
    except Exception:
        pass
        
    return findings

async def run_cors_scan(target_url, log_callback=None, headers=None):
    findings = []
    if log_callback: log_callback(f"🔓 Checking CORS Configuration on {target_url}...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        cors_findings = await check_cors(session, target_url)
        findings.extend(cors_findings)
        
    return findings