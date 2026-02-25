import random
import string
import time
import aiohttp
import asyncio

# [OAST CONFIG]
# In a real enterprise setup, this would point to a self-hosted OAST server (Interactsh/Burp Collab)
# Since this is a local scanner, we use a placeholder or public service if configured
DEFAULT_OAST_DOMAIN = "oast.lockon-scanner.local" # Placeholder for simulation

class OASTManager:
    def __init__(self, callback_host=None):
        self.callback_host = callback_host if callback_host else DEFAULT_OAST_DOMAIN
        self.active_payloads = {} # {id: {"type": "SSRF", "timestamp": ...}}
        self.interactions = []    # Store confirmed interactions

    def get_oast_domain(self):
        return self.callback_host

    def generate_payload(self, vuln_type="Generic"):
        """
        Generates a unique OAST payload (URL) tracking the vulnerability type.
        Format: http://<unique_id>.<vuln_type>.<callback_host>
        """
        unique_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        
        # Prepare the domain
        full_domain = f"{unique_id}.{vuln_type.lower()}.{self.callback_host}"
        payload_url = f"http://{full_domain}"
        
        self.active_payloads[unique_id] = {
            "type": vuln_type,
            "domain": full_domain,
            "url": payload_url,
            "timestamp": time.time()
        }
        
        return payload_url, unique_id

    async def check_interactions(self, session=None):
        """
        Polls for OAST interactions.
        
        Strategy:
        1. If callback_host is the default placeholder → use DNS-based simulation
        2. If callback_host is a real Interactsh server → poll the API
        3. Returns list of confirmed interaction dicts
        """
        confirmed = []
        
        # Skip if no active payloads to check
        if not self.active_payloads:
            return confirmed
        
        # [MODE 1] Simulation mode (placeholder domain)
        if self.callback_host == DEFAULT_OAST_DOMAIN:
            # In simulation mode, we cannot actually receive callbacks
            # Log that we're in simulation and return empty
            # Real deployment would use Interactsh or custom DNS server
            return confirmed
        
        # [MODE 2] Real OAST server — poll via HTTP API
        own_session = False
        if session is None:
            session = aiohttp.ClientSession()
            own_session = True
        
        try:
            poll_url = f"http://{self.callback_host}/poll"
            
            try:
                async with session.get(
                    poll_url, 
                    timeout=aiohttp.ClientTimeout(total=5),
                    ssl=False
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        # Expected format: {"interactions": [{"id": "abc123", "type": "dns", ...}]}
                        raw_interactions = data.get("interactions", [])
                        
                        for interaction in raw_interactions:
                            iid = interaction.get("id", "")
                            # Match interaction ID against our active payloads
                            for payload_id, payload_info in self.active_payloads.items():
                                if payload_id in iid or iid in payload_info.get("domain", ""):
                                    hit = {
                                        "payload_id": payload_id,
                                        "vuln_type": payload_info["type"],
                                        "interaction_type": interaction.get("type", "unknown"),
                                        "remote_address": interaction.get("remote_address", ""),
                                        "timestamp": interaction.get("timestamp", time.time()),
                                        "raw": interaction
                                    }
                                    confirmed.append(hit)
                                    self.interactions.append(hit)
                                    
            except (aiohttp.ClientError, asyncio.TimeoutError, Exception):
                # OAST server unreachable — not a fatal error
                pass
                
        finally:
            if own_session:
                await session.close()
        
        return confirmed

    def get_confirmed_vulns(self):
        """
        Returns all confirmed out-of-band interactions (proven vulnerabilities).
        """
        return self.interactions

    def clear_expired(self, max_age_seconds=3600):
        """
        Removes payloads older than max_age_seconds to prevent memory bloat.
        """
        now = time.time()
        expired = [pid for pid, info in self.active_payloads.items() 
                   if now - info.get("timestamp", 0) > max_age_seconds]
        for pid in expired:
            del self.active_payloads[pid]
        return len(expired)

# Singleton Instance
oast_manager = OASTManager()
