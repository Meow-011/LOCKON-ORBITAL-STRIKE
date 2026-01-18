import time
import random
import math
import re
from urllib.parse import urlparse, parse_qs, quote

class CortexBrain:
    """
    The AI Brain of LOCKON (Project CORTEX).
    Responsible for adaptive evasion, stealth timing, and decision making.
    """
    def __init__(self):
        self.error_rate = 0.0
        self.request_count = 0
        self.block_count = 0 # 403/429
        self.base_delay = 1.0 # Initial delay in seconds
        self.aggression_level = 5 # 1-10 (10 = Fast/Loud, 1 = Stealth)
        
    def analyze_attack_surface(self, url):
        """
        [PHASE 31] Context-Aware Analysis.
        Reads URL structure and query params to guess potential vulnerabilities.
        """
        suggestions = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # [HEURISTIC] Vulnerability Pattern Matching
        patterns = {
            "LFI": [r"(?i)(file|path|doc|root|dir|folder)"],
            "RCE": [r"(?i)(cmd|exec|command|ping|query|code)"],
            "SQLi": [r"(?i)(id|user|num|item|order|sort|q|search)"],
            "SSRF": [r"(?i)(url|link|src|target|dest|proxy)"],
            "XSS": [r"(?i)(q|search|name|title|msg|callback|return)"],
            "IDOR": [r"(?i)(id|user_id|account|order_id)"],
            "OpenRedirect": [r"(?i)(next|return|url|goto|redirect)"]
        }
        
        for p_name in params:
            for vuln, regex_list in patterns.items():
                for pattern in regex_list:
                    if re.search(pattern, p_name):
                        if vuln not in suggestions:
                            suggestions.append(vuln)
                            
        return suggestions

    def mutate_payload(self, payload, attack_type="Generic"):
        """
        [PHASE 32] Smart Mutation Engine.
        Transforms payloads to bypass WAFs.
        """
        mutations = [payload] # Always include original
        
        # 1. URL Encoding
        mutations.append(quote(payload))
        
        # 2. Double URL Encoding
        mutations.append(quote(quote(payload)))
        
        # 3. Strategy specific
        if attack_type == "SQLi":
            # Comment Injection (Space Bypass)
            if " " in payload:
                mutations.append(payload.replace(" ", "/**/"))
                mutations.append(payload.replace(" ", "%09")) # Tab
                mutations.append(payload.replace(" ", "+")) 
            
            # Case Toggling (Random)
            mutated_case = "".join([c.upper() if random.random() > 0.5 else c.lower() for c in payload])
            mutations.append(mutated_case)
            
        elif attack_type == "XSS":
            # Tag variations
            if "<script>" in payload:
                mutations.append(payload.replace("<script>", "<sCrIpT>"))
                mutations.append(payload.replace("<script>", "<script >")) # Space padding
                mutations.append(payload.replace("<script>", "<svg/onload="))
            
            # Quote toggling
            if '"' in payload:
                mutations.append(payload.replace('"', "'"))
                
        return list(set(mutations)) # Return unique set

    def record_response(self, status_code):
        """
        Feed response data to the brain to adjust behavior.
        """
        self.request_count += 1
        if status_code in [403, 429, 406]:
            self.block_count += 1
            self.adapt_to_block()
        elif status_code == 200:
            # Slowly decay block count (healing)
            if self.block_count > 0 and self.request_count % 10 == 0:
                self.block_count = max(0, self.block_count - 1)
                
    def adapt_to_block(self):
        """
        Reaction logic when blocked.
        """
        # Increase delay significantly
        self.base_delay = min(10.0, self.base_delay * 1.5)
        # Reduce aggression
        self.aggression_level = max(1, self.aggression_level - 1)
        
    def calculate_stealth_delay(self):
        """
        Calculate dynamic sleep time with Jitter.
        """
        # Base calculation based on aggression
        # Level 10 = 0.1s, Level 1 = 2.0s
        target_delay = self.base_delay + (10 - self.aggression_level) * 0.2
        
        # Add Jitter (+/- 30%) to look human
        jitter = random.uniform(-0.3, 0.3) * target_delay
        final_delay = max(0.1, target_delay + jitter)
        
        return final_delay

    def sleep(self):
        """
        Smart sleep wrapper.
        """
        delay = self.calculate_stealth_delay()
        time.sleep(delay)
        return delay
