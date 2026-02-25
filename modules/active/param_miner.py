import aiohttp
import asyncio
from urllib.parse import urlparse, urlencode, parse_qs

# คำยอดฮิตที่ Dev ชอบใช้ตั้งชื่อตัวแปรลับ
HIDDEN_PARAMS = [
    "debug", "admin", "test", "system", "root", "role",
    "access", "source", "backup", "log", "trace", "mode",
    "dev", "development", "config", "reset", "secret", "token",
    "cmd", "exec", "command", "shell", "upload", "file"
]

async def get_baseline(session, url):
    """ เก็บค่าหน้าเว็บปกติเพื่อเอาไว้เทียบ """
    try:
        async with session.get(url, timeout=5, ssl=False) as resp:
            text = await resp.text()
            return len(text), resp.status
    except Exception:
        return 0, 0

async def mine_params(session, url, baseline_len, baseline_status):
    findings = []
    
    # 1. เทคนิค Fuzzing: ลองใส่ Parameter เข้าไปดื้อๆ
    # เช่น example.com/?debug=true
    tasks = []
    
    # ฟังก์ชันย่อยสำหรับเช็คแต่ละ Param
    async def check_param(param):
        target = f"{url}?{param}=true" if "?" not in url else f"{url}&{param}=true"
        try:
            async with session.get(target, timeout=5, ssl=False) as resp:
                text = await resp.text()
                curr_len = len(text)
                
                # Logic: ถ้าใส่แล้วหน้าเว็บเปลี่ยนไปจากเดิมอย่างมีนัยสำคัญ
                # (ขนาดเปลี่ยนเกิน 5% หรือ Status Code เปลี่ยน)
                len_diff = abs(curr_len - baseline_len)
                is_significant = len_diff > (baseline_len * 0.05) + 50 # +50 bytes buffer
                
                if resp.status != baseline_status or (is_significant and resp.status == 200):
                    # กรอง False Positive
                    if resp.status == 404: return None
                    
                    detail = f"Hidden parameter '{param}' caused a different response."
                    if resp.status != baseline_status:
                        detail += f" (Status changed: {baseline_status} -> {resp.status})"
                    
                    return {
                        "type": "Hidden Parameter Discovered",
                        "severity": "Medium",
                        "detail": detail,
                        "evidence": f"Param: {param}\nURL: {target}\nLength Diff: {len_diff} bytes",
                        "remediation": "Ensure debug parameters are removed in production."
                    }
        except Exception: pass
        return None

    # สร้าง Task ยิงพร้อมกัน
    for param in HIDDEN_PARAMS:
        tasks.append(check_param(param))
        
    results = await asyncio.gather(*tasks)
    for res in results:
        if res: findings.append(res)
            
    return findings

async def run_param_miner(target_url, log_callback=None, headers=None):
    findings = []
    # ตัด Query string ออกก่อนเพื่อหา Hidden param ที่ระดับ Root
    base_url = target_url.split("?")[0]
    
    if log_callback: log_callback(f"👻 Mining for hidden debug parameters on {base_url}...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        # 1. หา Baseline
        base_len, base_status = await get_baseline(session, base_url)
        if base_len == 0: return []
        
        # 2. เริ่มขุด
        findings = await mine_params(session, base_url, base_len, base_status)
        
    return findings