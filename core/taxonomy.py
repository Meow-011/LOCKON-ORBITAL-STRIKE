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
