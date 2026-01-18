from core.kb import kb
import re

class KillChain:
    def __init__(self):
        pass
        
    def process_finding(self, finding):
        """
        Analyzes a finding to see if it provides 'Loot' for the Knowledge Base.
        """
        f_type = finding.get("type", "")
        f_evidence = finding.get("evidence", "")
        f_detail = finding.get("detail", "")
        
        # 1. Harvest Emails / Users
        if "Email Found" in f_type or "PII" in f_type:
            # Try to extract email from evidence or detail
            emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', f_evidence + f_detail)
            for email in emails:
                if kb.add_user(email):
                    print(f"[KILL CHAIN] 🧠 Learned User: {email}")
                    
        # 2. Harvest Tokens (JWT / Keys)
        if "JWT" in f_type or "Token" in f_type or "Key" in f_type:
             # Try to extract Bearer token structure
             # eyJ...
             jwt_matches = re.findall(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', f_evidence + f_detail)
             for token in jwt_matches:
                 if kb.add_token(token):
                     print(f"[KILL CHAIN] 🔑 Captured Token! Auto-upgrading scan privileges.")

        # 3. Harvest Credentials
        if "Default Credentials" in f_type or "Weak Password" in f_type:
            # Heuristic extraction. "Admin / admin"
            # This is hard to normalize without structured output from module.
            # But usually evidence says "Found: admin/123456"
            pass

    def enrich_headers(self, headers):
        """
        Updates headers with captured tokens to enable Authenticated Scanning.
        """
        best_token = kb.get_best_token()
        if best_token:
            headers["Authorization"] = f"Bearer {best_token}"
            headers["X-Access-Token"] = best_token # Just in case
        return headers

    def notify_waf_block(self):
        """
        Tracks number of WAF blocks.
        """
        # Could use a counter in KB
        # print("WAF Blocked a request.")
        pass

# Singleton
kill_chain = KillChain()
