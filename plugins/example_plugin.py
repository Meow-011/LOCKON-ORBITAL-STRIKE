"""
Example LOCKON Plugin
Demonstrates how to create a custom scan plugin.
"""
from core.plugin_loader import LockonPlugin


class HeaderSecurityPlugin(LockonPlugin):
    """Checks for missing security headers on the target."""
    
    name = "Header Security Check"
    version = "1.0"
    author = "LOCKON"
    description = "Checks for missing HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)"
    category = "recon"
    
    EXPECTED_HEADERS = {
        "Content-Security-Policy": {
            "severity": "MEDIUM",
            "description": "Content-Security-Policy header is not set",
            "cwe": "CWE-693",
        },
        "Strict-Transport-Security": {
            "severity": "MEDIUM", 
            "description": "HTTP Strict Transport Security (HSTS) header is not set",
            "cwe": "CWE-523",
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "description": "X-Frame-Options header is not set (clickjacking risk)",
            "cwe": "CWE-1021",
        },
        "X-Content-Type-Options": {
            "severity": "LOW",
            "description": "X-Content-Type-Options header is not set",
            "cwe": "CWE-693",
        },
        "X-XSS-Protection": {
            "severity": "LOW",
            "description": "X-XSS-Protection header is not set",
            "cwe": "CWE-79",
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "description": "Referrer-Policy header is not set",
            "cwe": "CWE-200",
        },
        "Permissions-Policy": {
            "severity": "INFO",
            "description": "Permissions-Policy header is not set",
            "cwe": "CWE-693",
        },
    }
    
    async def run(self, target, session=None, findings=None):
        """Check target for missing security headers."""
        results = []
        
        if not session:
            self.log("⚠️ No session available, skipping header check")
            return results
        
        try:
            async with session.get(target, ssl=False, timeout=10) as resp:
                response_headers = {k.lower(): v for k, v in resp.headers.items()}
                
                for header_name, info in self.EXPECTED_HEADERS.items():
                    if header_name.lower() not in response_headers:
                        results.append({
                            "type": "Missing Security Header",
                            "severity": info["severity"],
                            "detail": f"{info['description']} — Target: {target}",
                            "url": target,
                            "cwe": info["cwe"],
                            "remediation": f"Add the '{header_name}' header to your server responses.",
                        })
                        self.log(f"  ⚠️ Missing: {header_name}")
                    else:
                        self.log(f"  ✅ Present: {header_name}")
        except Exception as e:
            self.log(f"Header check error: {e}")
        
        return results
