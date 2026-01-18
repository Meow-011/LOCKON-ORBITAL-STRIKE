import base64
import zlib
import random
import string

class Obfuscator:
    @staticmethod
    def _random_var(length=6):
        return ''.join(random.choices(string.ascii_letters, k=length))

    @staticmethod
    def obfuscate_python(payload):
        """
        Compresses and Base64 encodes Python payload.
        Wraps it in a random variable execution.
        """
        # 1. Compress & Encode
        compressed = zlib.compress(payload.encode())
        b64 = base64.b64encode(compressed).decode()
        
        # 2. Key Variables
        var_payload = Obfuscator._random_var()
        var_exec = Obfuscator._random_var()
        
        # 3. Construct Obfuscated Script
        stub = f"""
import zlib, base64, sys

{var_payload} = "{b64}"

try:
    exec(zlib.decompress(base64.b64decode({var_payload})).decode())
except Exception as e:
    pass
"""
        return stub.strip()

    @staticmethod
    def obfuscate_powershell(payload):
        """
        Encodes PowerShell script to Base64 and wraps in execution stub.
        """
        # Convert to UTF-16LE for PowerShell B64
        bytes_payload = payload.encode('utf-16le')
        b64 = base64.b64encode(bytes_payload).decode()
        
        # Encoded Command Wrapper
        wrapper = f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {b64}"
        
        # If the user wants a script file (.ps1) rather than a one-liner command:
        # We can just return the command to be put in a batch file or run directly.
        # But for !generate, we usually save as a file. 
        # Let's save a batch wrapper that runs the powershell.
        
        return f"@echo off\n{wrapper}\nexit"

    @staticmethod
    def obfuscate_bash(payload):
        """
        Base64 encodes Bash payload.
        """
        b64 = base64.b64encode(payload.encode()).decode()
        stub = f"echo {b64} | base64 -d | bash"
        return stub

    @staticmethod
    def obfuscate(content, payload_type):
        if "python" in payload_type.lower():
            return Obfuscator.obfuscate_python(content)
        elif "powershell" in payload_type.lower():
            return Obfuscator.obfuscate_powershell(content)
        elif "bash" in payload_type.lower():
            return Obfuscator.obfuscate_bash(content)
        return content
