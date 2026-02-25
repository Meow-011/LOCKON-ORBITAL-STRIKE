import subprocess
import shutil
import asyncio
import os
import platform
import json # [FIX] Import at top

PROJECT_DIR = os.getcwd()
BIN_DIR = os.path.join(PROJECT_DIR, "bin")

def get_binary_path(tool_name):
    system_path = shutil.which(tool_name)
    if system_path: return system_path
    
    # Check inside bin folder
    exe_name = tool_name
    if platform.system() == "Windows" and not tool_name.endswith(".exe"):
        exe_name += ".exe"
        
    local_path = os.path.join(BIN_DIR, exe_name)
    if os.path.exists(local_path): return local_path
    return None

NMAP_PATH = get_binary_path("nmap")
SUBFINDER_PATH = get_binary_path("subfinder")
NUCLEI_PATH = get_binary_path("nuclei")

async def run_port_scan(target, log_callback=None):
    if not NMAP_PATH: return []
    hostname = target.replace("http://", "").replace("https://", "").split("/")[0]
    if log_callback: log_callback(f"🛡️ Executing Nmap on {hostname}...")
    
    cmd = f'"{NMAP_PATH}" -F -T4 {hostname}'
    try:
        process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await process.communicate()
        output = stdout.decode(errors='ignore')
        
        open_ports = []
        for line in output.split("\n"):
            if "open" in line and "tcp" in line:
                open_ports.append(line.strip())
        
        if open_ports:
            return [{"type": "Open Port", "severity": "Info", "detail": p, "evidence": "Nmap Scan"} for p in open_ports]
    except Exception: pass
    return []

from urllib.parse import urlparse

async def run_subdomain_enum(target, log_callback=None):
    if not SUBFINDER_PATH: return []
    
    try:
        # Robust parsing
        if "://" not in target: target = "http://" + target
        parsed = urlparse(target)
        domain = parsed.netloc.split(":")[0] # Remove port if present
    except Exception:
        domain = target.replace("http://", "").replace("https://", "").split("/")[0]

    if log_callback: log_callback(f"🔍 Enforcing Subdomain Discovery on {domain}...")
    
    cmd = f'"{SUBFINDER_PATH}" -d {domain} -silent'
    subs = []
    try:
        process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await process.communicate()
        output = stdout.decode(errors='ignore')
        subs = [line.strip() for line in output.split("\n") if line.strip()]
        
        if log_callback: log_callback(f"   Found {len(subs)} subdomains.")
        # [FIX] Added evidence field for UI aggregation support
        return [{"type": "Subdomain Found", "severity": "Info", "detail": s, "evidence": s} for s in subs]
    except Exception: pass
    return []

async def run_nuclei_scan(target, log_callback=None, headers=None):
    if not NUCLEI_PATH: 
        if log_callback: log_callback("⚠️ Nuclei not found. Skipping vulnerability scan.")
        return []
        
    if log_callback: log_callback(f"☢️  Launching Nuclei (The Nuclear Option)...")
    
    # Construct base command
    cmd = f'"{NUCLEI_PATH}" -u {target} -tags cves,misconfig,exposure -severity low,medium,high,critical -json'
    
    # Add Evasion Headers to Nuclei
    if headers:
        for k, v in headers.items():
            # Escape double quotes just in case, though headers usually simple
            safe_val = v.replace('"', '\\"')
            cmd += f' -H "{k}: {safe_val}"'

    findings = []
    try:
        process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await process.communicate()
        output = stdout.decode(errors='ignore')

        for line in output.split("\n"):
            line = line.strip()
            if not line: continue
            # [FIX] Robust JSON parsing
            if not line.startswith("{"): continue
            
            try:
                data = json.loads(line)
                info = data.get('info', {})
                findings.append({
                    "type": f"Nuclei: {info.get('name')}",
                    "severity": info.get('severity', 'info').capitalize(),
                    "detail": info.get('description', 'Detected by Nuclei'),
                    "evidence": f"Matcher: {data.get('matcher-name')}\nURL: {data.get('matched-at')}"
                })
            except Exception: pass
            
        if findings and log_callback:
            log_callback(f"☢️  Nuclei found {len(findings)} issues!")
            
    except Exception as e:
        if log_callback: log_callback(f"❌ Nuclei Error: {e}")
        
    return findings