import random
import string
import uuid

# [OAST CONFIG]
# In a real enterprise setup, this would point to a self-hosted OAST server (Interactsh/Burp Collab)
# Since this is a local scanner, we use a placeholder or public service if configured
DEFAULT_OAST_DOMAIN = "oast.lockon-scanner.local" # Placeholder for simulation

class OASTManager:
    def __init__(self, callback_host=None):
        self.callback_host = callback_host if callback_host else DEFAULT_OAST_DOMAIN
        self.active_payloads = {} # {id: {"type": "SSRF", "timestamp": ...}}

    def get_oast_domain(self):
        return self.callback_host

    def generate_payload(self, vuln_type="Generic"):
        """
        Generates a unique OAST payload (URL) tracking the vulnerability type.
        Format: http://<unique_id>.<vuln_type>.<callback_host>
        """
        unique_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        
        # Prepare the domain
        # If using a real wildcard DNS OAST, it looks like: abc1234.ssrf.attacker.com
        # If using a placeholder, it's just for logging "what would happen"
        full_domain = f"{unique_id}.{vuln_type.lower()}.{self.callback_host}"
        
        payload_url = f"http://{full_domain}"
        
        self.active_payloads[unique_id] = {
            "type": vuln_type,
            "domain": full_domain,
            "url": payload_url
        }
        
        return payload_url, unique_id

    def check_interactions(self):
        """
        In a real system, this queries the Interactsh/Collaborator API.
        For simulation, we return empty list or mock data manually if needed.
        """
        # TODO: Implement Interactsh Client API here
        return []

# Singleton Instance
oast_manager = OASTManager()
