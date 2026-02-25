class FindingCategory:
    INJECTION = "Injection"
    AUTHENTICATION = "Authentication"
    AUTHORIZATION = "Authorization"
    SESSION_TOKEN = "Session & Token"
    CLIENT_SIDE = "Client-Side"
    FILE_HANDLING = "File Handling"
    API = "API Security"
    MISCONFIGURATION = "Security Misconfiguration"
    CRYPTOGRAPHY = "Cryptography"
    INFO_DISCLOSURE = "Information Disclosure"
    UNCATEGORIZED = "Uncategorized"


# --- CWE Mapping ---
CWE_MAP = {
    # Injection
    "SQL Injection": "CWE-89", "SQLi": "CWE-89",
    "NoSQL Injection": "CWE-943",
    "Command Injection": "CWE-78", "OS Command Injection": "CWE-78", "RCE": "CWE-78",
    "Remote Code Execution": "CWE-94",
    "LDAP Injection": "CWE-90",
    "XPath Injection": "CWE-643",
    "SSTI": "CWE-1336", "Template Injection": "CWE-1336",
    "XXE Injection": "CWE-611", "XXE": "CWE-611",
    "Log4Shell": "CWE-917",
    "Deserialization": "CWE-502",
    
    # Client-Side
    "XSS": "CWE-79", "Cross-Site Scripting": "CWE-79",
    "XSS (Reflected)": "CWE-79", "XSS (Stored)": "CWE-79", "DOM XSS": "CWE-79",
    "CSRF": "CWE-352", "Cross-Site Request Forgery": "CWE-352",
    "Clickjacking": "CWE-1021",
    "Open Redirect": "CWE-601",
    "CORS Misconfiguration": "CWE-942",
    "Prototype Pollution": "CWE-1321",
    "CRLF Injection": "CWE-93",
    
    # Auth
    "Authentication Bypass": "CWE-287", "Auth Bypass": "CWE-287",
    "IDOR": "CWE-639", "Insecure Direct Object Reference": "CWE-639",
    "JWT Vulnerability": "CWE-347",
    "Default Credentials": "CWE-798",
    "Privilege Escalation": "CWE-269",
    "Brute-force": "CWE-307",
    
    # File
    "LFI": "CWE-98", "Local File Inclusion": "CWE-98",
    "Path Traversal": "CWE-22", "Directory Traversal": "CWE-22",
    "File Upload": "CWE-434", "File Upload RCE": "CWE-434",
    
    # Server
    "SSRF": "CWE-918",
    "HTTP Request Smuggling": "CWE-444",
    "Host Header Injection": "CWE-644",
    "Race Condition": "CWE-362",
    
    # Misconfig
    "Missing Security Headers": "CWE-693",
    "Directory Listing": "CWE-548",
    "Error Message Disclosure": "CWE-209", "Verbose Error": "CWE-209",
    "Git Repository Exposed": "CWE-538",
    "Backup File Found": "CWE-530",
    "Bucket Misconfiguration": "CWE-732",
    "Subdomain Takeover": "CWE-754",
    
    # Crypto
    "SSL/TLS Weakness": "CWE-326",
    "Weak Cipher": "CWE-327",
    "Secrets in Source": "CWE-798", "API Key Exposed": "CWE-798",
    "Cookie Without Secure Flag": "CWE-614",
    "Cookie Without HttpOnly": "CWE-1004",
    
    # API
    "GraphQL Introspection": "CWE-200",
    "Mass Assignment": "CWE-915",
    "API": "CWE-200",
}

# --- OWASP Top 10 (2021) Mapping ---
OWASP_MAP = {
    # A01:2021 Broken Access Control
    "IDOR": "A01:2021", "Insecure Direct Object Reference": "A01:2021",
    "Path Traversal": "A01:2021", "Directory Traversal": "A01:2021",
    "CORS Misconfiguration": "A01:2021",
    "Privilege Escalation": "A01:2021",
    "Directory Listing": "A01:2021",
    
    # A02:2021 Cryptographic Failures
    "SSL/TLS Weakness": "A02:2021", "Weak Cipher": "A02:2021",
    "Secrets in Source": "A02:2021", "API Key Exposed": "A02:2021",
    "Cookie Without Secure Flag": "A02:2021",
    
    # A03:2021 Injection
    "SQL Injection": "A03:2021", "SQLi": "A03:2021",
    "NoSQL Injection": "A03:2021",
    "Command Injection": "A03:2021", "OS Command Injection": "A03:2021",
    "LDAP Injection": "A03:2021",
    "XSS": "A03:2021", "Cross-Site Scripting": "A03:2021",
    "XSS (Reflected)": "A03:2021", "XSS (Stored)": "A03:2021", "DOM XSS": "A03:2021",
    "XXE Injection": "A03:2021", "XXE": "A03:2021",
    "SSTI": "A03:2021", "Template Injection": "A03:2021",
    "CRLF Injection": "A03:2021",
    "Host Header Injection": "A03:2021",
    
    # A04:2021 Insecure Design
    "Race Condition": "A04:2021",
    "CSRF": "A04:2021",
    
    # A05:2021 Security Misconfiguration
    "Missing Security Headers": "A05:2021",
    "Error Message Disclosure": "A05:2021", "Verbose Error": "A05:2021",
    "Default Credentials": "A05:2021",
    "Git Repository Exposed": "A05:2021",
    "Backup File Found": "A05:2021",
    "Bucket Misconfiguration": "A05:2021",
    "GraphQL Introspection": "A05:2021",
    "Admin Panel Found": "A05:2021",
    
    # A06:2021 Vulnerable and Outdated Components
    "Log4Shell": "A06:2021", "Spring4Shell": "A06:2021",
    "Deserialization": "A06:2021",
    "Prototype Pollution": "A06:2021",
    
    # A07:2021 Identification and Authentication Failures
    "Authentication Bypass": "A07:2021", "Auth Bypass": "A07:2021",
    "JWT Vulnerability": "A07:2021",
    "Brute-force": "A07:2021",
    "Cookie Without HttpOnly": "A07:2021",
    
    # A08:2021 Software and Data Integrity Failures
    "File Upload": "A08:2021", "File Upload RCE": "A08:2021",
    "Subdomain Takeover": "A08:2021",
    
    # A09:2021 Security Logging and Monitoring Failures
    # (Usually not directly detected)
    
    # A10:2021 Server-Side Request Forgery
    "SSRF": "A10:2021",
}

OWASP_NAMES = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}


def get_cwe(finding_type):
    """Get CWE-ID for a finding type with fuzzy matching."""
    if finding_type in CWE_MAP:
        return CWE_MAP[finding_type]
    ftype_lower = finding_type.lower()
    for key, cwe in CWE_MAP.items():
        if key.lower() in ftype_lower or ftype_lower in key.lower():
            return cwe
    return None

def get_owasp(finding_type):
    """Get OWASP Top 10 ID + name for a finding type with fuzzy matching."""
    def _lookup(ft):
        if ft in OWASP_MAP:
            code = OWASP_MAP[ft]
            return f"{code} {OWASP_NAMES.get(code, '')}"
        return None
    
    result = _lookup(finding_type)
    if result: return result
    
    ftype_lower = finding_type.lower()
    for key in OWASP_MAP:
        if key.lower() in ftype_lower or ftype_lower in key.lower():
            code = OWASP_MAP[key]
            return f"{code} {OWASP_NAMES.get(code, '')}"
    return None

class TaxonomyMapper:
    """
    Maps finding types to their respective categories based on keywords.
    """
    
    # Priority mapping: Keywords to Categories
    # Order matters slightly for overlapping keywords, but specific matches should be fine.
    KEYWORD_MAP = {
        # 1. Injection
        "SQL Injection": FindingCategory.INJECTION,
        "SQLi": FindingCategory.INJECTION,
        "NoSQL": FindingCategory.INJECTION,
        "Command Injection": FindingCategory.INJECTION,
        "RCE": FindingCategory.INJECTION,
        "Remote Code Execution": FindingCategory.INJECTION,
        "SSTI": FindingCategory.INJECTION,
        "Template Injection": FindingCategory.INJECTION,
        "XPath": FindingCategory.INJECTION,
        "LDAP": FindingCategory.INJECTION,
        "Log4Shell": FindingCategory.INJECTION,
        "Spring Cloud": FindingCategory.INJECTION, # Spring Cloud Function RCE

        # 2. Authentication
        "Login": FindingCategory.AUTHENTICATION,
        "Password": FindingCategory.AUTHENTICATION,
        "Credential": FindingCategory.AUTHENTICATION,
        "Auth Bypass": FindingCategory.AUTHENTICATION,
        "Authentication": FindingCategory.AUTHENTICATION,
        "Brute-force": FindingCategory.AUTHENTICATION,
        "Default Credentials": FindingCategory.AUTHENTICATION,

        # 3. Authorization
        "IDOR": FindingCategory.AUTHORIZATION,
        "Insecure Direct Object Reference": FindingCategory.AUTHORIZATION,
        "Privilege Escalation": FindingCategory.AUTHORIZATION,
        "Access Control": FindingCategory.AUTHORIZATION,
        "Unauthorized": FindingCategory.AUTHORIZATION,
        "Bypass": FindingCategory.AUTHORIZATION, # Generic bypass often falls here or Auth

        # 4. Session & Token
        "Cookie": FindingCategory.SESSION_TOKEN,
        "Session": FindingCategory.SESSION_TOKEN,
        "JWT": FindingCategory.SESSION_TOKEN,
        "Token": FindingCategory.SESSION_TOKEN,

        # 5. Client-Side
        "XSS": FindingCategory.CLIENT_SIDE,
        "Cross-Site Scripting": FindingCategory.CLIENT_SIDE,
        "CSRF": FindingCategory.CLIENT_SIDE,
        "Cross-Site Request Forgery": FindingCategory.CLIENT_SIDE,
        "Clickjacking": FindingCategory.CLIENT_SIDE,
        "Redirect": FindingCategory.CLIENT_SIDE, # Open Redirect
        "CORS": FindingCategory.CLIENT_SIDE,
        "DOM": FindingCategory.CLIENT_SIDE,

        # 6. File Handling
        "File Upload": FindingCategory.FILE_HANDLING,
        "Arbitrary File": FindingCategory.FILE_HANDLING,
        "LFI": FindingCategory.FILE_HANDLING,
        "Local File Inclusion": FindingCategory.FILE_HANDLING,
        "Path Traversal": FindingCategory.FILE_HANDLING,
        "Directory Traversal": FindingCategory.FILE_HANDLING,
        "File Read": FindingCategory.FILE_HANDLING,
        "File Disclosure": FindingCategory.FILE_HANDLING,

        # 7. API Security
        "API": FindingCategory.API,
        "GraphQL": FindingCategory.API,
        "BOLA": FindingCategory.API,
        "Mass Assignment": FindingCategory.API,

        # 8. Security Misconfiguration
        "Debug": FindingCategory.MISCONFIGURATION,
        "Directory Listing": FindingCategory.MISCONFIGURATION,
        "Backup": FindingCategory.MISCONFIGURATION,
        "Config": FindingCategory.MISCONFIGURATION,
        "Exposed Panel": FindingCategory.MISCONFIGURATION,
        "Default Configuration": FindingCategory.MISCONFIGURATION,
        "WAF": FindingCategory.MISCONFIGURATION, # Often informational about WAF presence
        "Headers": FindingCategory.MISCONFIGURATION, # Security Headers

        # 9. Cryptography
        "Weak Hash": FindingCategory.CRYPTOGRAPHY,
        "Plaintext": FindingCategory.CRYPTOGRAPHY,
        "Hardcoded": FindingCategory.CRYPTOGRAPHY, # Hardcoded secrets
        "Secret": FindingCategory.CRYPTOGRAPHY,
        "SSL": FindingCategory.CRYPTOGRAPHY,
        "TLS": FindingCategory.CRYPTOGRAPHY,
        "Cipher": FindingCategory.CRYPTOGRAPHY,

        # 10. Information Disclosure
        "Disclosure": FindingCategory.INFO_DISCLOSURE,
        "Leak": FindingCategory.INFO_DISCLOSURE,
        "Error Message": FindingCategory.INFO_DISCLOSURE,
        "Stack Trace": FindingCategory.INFO_DISCLOSURE,
        "Version": FindingCategory.INFO_DISCLOSURE,
        "Metadata": FindingCategory.INFO_DISCLOSURE,
        "Git": FindingCategory.INFO_DISCLOSURE,
        "Subdomain": FindingCategory.INFO_DISCLOSURE, # Recon data
        "Port": FindingCategory.MISCONFIGURATION, # Open ports
        "Techno": FindingCategory.INFO_DISCLOSURE, # Tech detect
    }

    @staticmethod
    def classify(finding_type):
        """
        Classifies a finding type into a category based on keywords.
        """
        ftype_lower = str(finding_type).lower()
        
        # Check specific prioritized matches
        if "sql" in ftype_lower: return FindingCategory.INJECTION
        if "xss" in ftype_lower: return FindingCategory.CLIENT_SIDE
        if "cors" in ftype_lower: return FindingCategory.CLIENT_SIDE
        if "csrf" in ftype_lower: return FindingCategory.CLIENT_SIDE
        if "jwt" in ftype_lower: return FindingCategory.SESSION_TOKEN
        if "upload" in ftype_lower: return FindingCategory.FILE_HANDLING
        if "traversal" in ftype_lower or ("lfi" in ftype_lower): return FindingCategory.FILE_HANDLING
        if "redirect" in ftype_lower: return FindingCategory.CLIENT_SIDE
        if "debug" in ftype_lower: return FindingCategory.MISCONFIGURATION
        if "git" in ftype_lower: return FindingCategory.INFO_DISCLOSURE
        if "backup" in ftype_lower: return FindingCategory.MISCONFIGURATION
        
        # General loop for everything else
        for keyword, category in TaxonomyMapper.KEYWORD_MAP.items():
            if keyword.lower() in ftype_lower:
                return category
                
        # Default fallbacks for some ambiguous ones
        if "exposed" in ftype_lower: return FindingCategory.INFO_DISCLOSURE
        if "header" in ftype_lower: return FindingCategory.MISCONFIGURATION
        
        return FindingCategory.UNCATEGORIZED
