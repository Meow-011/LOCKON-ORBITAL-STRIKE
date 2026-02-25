"""
CVSS 3.1 Base Score Calculator
Implements the CVSS v3.1 specification for calculating base scores.
Reference: https://www.first.org/cvss/v3.1/specification-document
"""

class CVSSVector:
    """Represents a CVSS 3.1 Base Score vector."""
    
    # Metric value weights (from CVSS 3.1 spec)
    AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}  # Network, Adjacent, Local, Physical
    AC_WEIGHTS = {"L": 0.77, "H": 0.44}  # Low, High
    PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}  # None, Low, High (Scope Unchanged)
    PR_WEIGHTS_CHANGED   = {"N": 0.85, "L": 0.68, "H": 0.50}  # None, Low, High (Scope Changed)
    UI_WEIGHTS = {"N": 0.85, "R": 0.62}  # None, Required
    S_VALUES = {"U": False, "C": True}  # Unchanged, Changed
    CIA_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}  # High, Low, None
    
    def __init__(self, av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"):
        self.av = av
        self.ac = ac
        self.pr = pr
        self.ui = ui
        self.s = s
        self.c = c
        self.i = i
        self.a = a
    
    @classmethod
    def from_string(cls, vector_string):
        """Parse CVSS vector string like 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'"""
        parts = vector_string.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "")
        metrics = {}
        for part in parts.split("/"):
            if ":" in part:
                key, val = part.split(":", 1)
                metrics[key] = val
        return cls(
            av=metrics.get("AV", "N"), ac=metrics.get("AC", "L"),
            pr=metrics.get("PR", "N"), ui=metrics.get("UI", "N"),
            s=metrics.get("S", "U"), c=metrics.get("C", "H"),
            i=metrics.get("I", "H"), a=metrics.get("A", "H")
        )
    
    def to_string(self):
        return f"CVSS:3.1/AV:{self.av}/AC:{self.ac}/PR:{self.pr}/UI:{self.ui}/S:{self.s}/C:{self.c}/I:{self.i}/A:{self.a}"
    
    def calculate(self):
        """Calculate CVSS 3.1 Base Score. Returns (score, severity, vector_string)."""
        import math
        
        iss = 1 - ((1 - self.CIA_WEIGHTS[self.c]) * (1 - self.CIA_WEIGHTS[self.i]) * (1 - self.CIA_WEIGHTS[self.a]))
        
        scope_changed = self.S_VALUES[self.s]
        pr_weights = self.PR_WEIGHTS_CHANGED if scope_changed else self.PR_WEIGHTS_UNCHANGED
        
        exploitability = 8.22 * self.AV_WEIGHTS[self.av] * self.AC_WEIGHTS[self.ac] * pr_weights[self.pr] * self.UI_WEIGHTS[self.ui]
        
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        
        if impact <= 0:
            base_score = 0.0
        elif scope_changed:
            base_score = min(1.08 * (impact + exploitability), 10.0)
        else:
            base_score = min(impact + exploitability, 10.0)
        
        # Round up to 1 decimal (CVSS spec: "round up")
        base_score = math.ceil(base_score * 10) / 10
        
        severity = self._get_severity(base_score)
        return base_score, severity, self.to_string()
    
    @staticmethod
    def _get_severity(score):
        if score == 0.0: return "NONE"
        elif score <= 3.9: return "LOW"
        elif score <= 6.9: return "MEDIUM"
        elif score <= 8.9: return "HIGH"
        else: return "CRITICAL"


def calculate_cvss(vector_string):
    """Convenience function: calculate CVSS from vector string.
    
    Returns dict: { 'score': 9.8, 'severity': 'CRITICAL', 'vector': 'CVSS:3.1/...' }
    """
    v = CVSSVector.from_string(vector_string)
    score, severity, vector = v.calculate()
    return {"score": score, "severity": severity, "vector": vector}


# --- Default CVSS Vectors for common vulnerability types ---
# These are reasonable defaults; actual CVSS should be assessed per-finding.
DEFAULT_CVSS_VECTORS = {
    # === CRITICAL (9.0-10.0) ===
    "SQL Injection":                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",      # 9.8
    "Remote Code Execution":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",      # 9.8
    "Command Injection":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",      # 9.8
    "OS Command Injection":            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",      # 9.8
    "Deserialization RCE":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",      # 9.8
    "File Upload RCE":                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",      # 9.8
    "SSTI":                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",      # 9.8
    "Log4Shell":                       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",      # 10.0
    "Spring4Shell":                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",      # 9.8
    "NoSQL Injection":                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",      # 9.1
    "XXE Injection":                   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L",      # 8.6→9.1
    "Authentication Bypass":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",      # 9.1
    
    # === HIGH (7.0-8.9) ===
    "SSRF":                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",      # 8.2
    "XSS (Stored)":                    "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",      # 5.4→6.1
    "Cross-Site Scripting (Stored)":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",      # 6.1
    "LFI":                             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",      # 7.5
    "Path Traversal":                  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",      # 7.5
    "JWT Vulnerability":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",      # 9.1
    "IDOR":                            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",      # 8.1
    "Privilege Escalation":            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",      # 8.8
    "LDAP Injection":                  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",      # 8.2
    "HTTP Request Smuggling":          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",      # 7.4
    "Race Condition":                  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",      # 7.4
    "Admin Panel Found":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",      # 8.2
    "Default Credentials":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",      # 9.8
    "Prototype Pollution":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H",      # 7.3
    "Bucket Misconfiguration":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",      # 7.5
    "Git Repository Exposed":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",      # 7.5
    "Backup File Found":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",      # 7.5
    "Subdomain Takeover":              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",      # 7.2
    
    # === MEDIUM (4.0-6.9) ===
    "XSS (Reflected)":                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",      # 6.1
    "Cross-Site Scripting (Reflected)": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",     # 6.1
    "DOM XSS":                         "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",      # 6.1
    "CORS Misconfiguration":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",      # 6.5
    "Open Redirect":                   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",      # 6.1
    "CRLF Injection":                  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",      # 4.7
    "Clickjacking":                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",      # 4.3
    "CSRF":                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",      # 6.5
    "Host Header Injection":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",      # 4.3
    "Secrets in Source":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",      # 5.3
    "GraphQL Introspection":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",      # 5.3
    "API Key Exposed":                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",      # 7.5
    "Sensitive Data in URL":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",      # 5.3
    "WebSocket Vulnerability":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",      # 6.5
    
    # === LOW (0.1-3.9) ===
    "Missing Security Headers":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",      # 5.3→informational
    "Directory Listing":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",      # 5.3
    "SSL/TLS Weakness":                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",      # 5.9
    "Error Message Disclosure":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",      # 5.3
    "Verbose Error":                   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",      # 5.3
    "Cookie Without Secure Flag":      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",      # 3.1
    "Cookie Without HttpOnly":         "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",      # 3.1
    
    # === INFO (0.0) ===
    "Technology Detected":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",      # 0.0
    "Subdomain Found":                 "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",      # 0.0
    "Open Port":                       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",      # 0.0
    "WAF Detected":                    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",      # 0.0
    "HTTP Method Allowed":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",      # 0.0
    "CMS Detected":                    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",      # 0.0
    "Broken Link":                     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",      # 0.0
}


def get_cvss_for_finding(finding_type):
    """Get CVSS data for a finding type using fuzzy matching.
    
    Returns dict: { 'score': float, 'severity': str, 'vector': str }
    """
    # Exact match first
    if finding_type in DEFAULT_CVSS_VECTORS:
        return calculate_cvss(DEFAULT_CVSS_VECTORS[finding_type])
    
    # Fuzzy match: check if any key is contained in the finding type
    ftype_lower = finding_type.lower()
    for key, vector in DEFAULT_CVSS_VECTORS.items():
        if key.lower() in ftype_lower or ftype_lower in key.lower():
            return calculate_cvss(vector)
    
    # Keyword-based fallback
    keyword_vectors = {
        "sqli": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "sql": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rce": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "command": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "inject": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "auth": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "bypass": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "ssrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "lfi": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "traversal": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "upload": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cors": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cve": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "jwt": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "idor": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "header": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "cookie": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "leak": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "secret": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "error": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "ssl": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "tls": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "subdomain": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "port": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "detect": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "info": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
    }
    
    for kw, vec in keyword_vectors.items():
        if kw in ftype_lower:
            return calculate_cvss(vec)
    
    # Ultimate fallback: Medium severity
    return calculate_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
