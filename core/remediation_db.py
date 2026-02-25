"""
Remediation Database
Provides detailed fix guidance per vulnerability type, including code examples and references.
"""

REMEDIATION_DB = {
    # ===== INJECTION =====
    "SQL Injection": {
        "description": "SQL Injection allows attackers to interfere with database queries, potentially reading/modifying all data.",
        "risk": "Complete database compromise, data theft, authentication bypass, potential RCE via xp_cmdshell.",
        "fix_steps": [
            "Use parameterized queries (prepared statements) for ALL database interactions",
            "Use an ORM (SQLAlchemy, Hibernate, ActiveRecord) instead of raw SQL",
            "Implement input validation with whitelist approach",
            "Apply least-privilege database permissions",
            "Enable WAF rules for SQL injection patterns"
        ],
        "code_example": """# Python (Parameterized Query)
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Java (PreparedStatement)  
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, userId);

# PHP (PDO)
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $id]);""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/89.html"
        ]
    },
    
    "NoSQL Injection": {
        "description": "NoSQL Injection exploits query operators in NoSQL databases like MongoDB.",
        "risk": "Authentication bypass, data exfiltration, denial of service.",
        "fix_steps": [
            "Sanitize user input — reject objects/arrays where strings are expected",
            "Use MongoDB's $eq operator explicitly instead of implicit matching",
            "Implement schema validation at the database level",
            "Use an ODM library (Mongoose) with strict schemas"
        ],
        "code_example": """# Vulnerable (MongoDB)
db.users.find({ username: req.body.username, password: req.body.password })

# Fixed (Mongoose + type casting)
const user = await User.findOne({ 
    username: String(req.body.username), 
    password: String(req.body.password) 
});""",
        "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"]
    },
    
    "Command Injection": {
        "description": "OS Command Injection allows execution of arbitrary system commands on the host.",
        "risk": "Full server compromise, reverse shell, lateral movement, data destruction.",
        "fix_steps": [
            "NEVER pass user input to system commands",
            "Use language-native libraries instead of shell commands",
            "If shell commands are unavoidable, use parameterized APIs (subprocess with list args)",
            "Implement strict input validation with whitelist characters",
            "Run application with minimal OS privileges"
        ],
        "code_example": """# Vulnerable
os.system(f"ping {user_input}")

# Fixed (Python)
import subprocess
subprocess.run(["ping", "-c", "4", validated_host], capture_output=True)

# Fixed (use native library)
import socket
socket.gethostbyname(validated_host)""",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"]
    },

    "OS Command Injection": {
        "description": "OS Command Injection allows execution of arbitrary system commands on the host.",
        "risk": "Full server compromise, reverse shell, data destruction.",
        "fix_steps": [
            "NEVER concatenate user input into shell commands",
            "Use subprocess with list arguments (no shell=True)",
            "Implement strict whitelist validation",
            "Run with minimal privileges"
        ],
        "code_example": """# Vulnerable
os.system(f"nslookup {domain}")

# Fixed
subprocess.run(["nslookup", validated_domain], capture_output=True, shell=False)""",
        "references": ["https://cwe.mitre.org/data/definitions/78.html"]
    },
    
    # ===== XSS =====
    "Cross-Site Scripting (Reflected)": {
        "description": "Reflected XSS executes malicious scripts in a user's browser via crafted URLs.",
        "risk": "Session hijacking, credential theft, phishing, defacement.",
        "fix_steps": [
            "Encode all output using context-aware encoding (HTML, JS, URL, CSS)",
            "Implement Content-Security-Policy (CSP) headers",
            "Use frameworks that auto-escape output (React, Angular, Jinja2 with autoescape)",
            "Validate and sanitize input on server-side",
            "Set HttpOnly and Secure flags on cookies"
        ],
        "code_example": """# Python/Jinja2 (auto-escape ON by default)
{{ user_input }}  {# auto-escaped #}
{{ user_input | e }}  {# explicit escape #}

# JavaScript (DOM safe)
element.textContent = userInput;  // Safe
element.innerHTML = userInput;    // DANGEROUS

# CSP Header
Content-Security-Policy: default-src 'self'; script-src 'self'""",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"]
    },

    "XSS (Reflected)": {
        "description": "Reflected XSS executes malicious scripts via crafted URLs.",
        "risk": "Session hijacking, credential theft, phishing.",
        "fix_steps": ["Encode output contextually", "Implement CSP headers", "Use auto-escaping frameworks"],
        "code_example": """Content-Security-Policy: default-src 'self'; script-src 'self'""",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"]
    },

    "DOM XSS": {
        "description": "DOM-based XSS occurs when client-side JavaScript processes untrusted data.",
        "risk": "Session hijacking, credential theft without server interaction.",
        "fix_steps": [
            "Avoid using innerHTML, document.write, eval with user data",
            "Use textContent or innerText for display",
            "Sanitize with DOMPurify before rendering HTML",
            "Implement strict CSP"
        ],
        "code_example": """// Vulnerable
document.getElementById('output').innerHTML = location.hash.slice(1);

// Fixed
document.getElementById('output').textContent = location.hash.slice(1);

// With DOMPurify (when HTML is needed)
document.getElementById('output').innerHTML = DOMPurify.sanitize(userInput);""",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"]
    },
    
    # ===== AUTH =====
    "Authentication Bypass": {
        "description": "Authentication bypass allows access to protected resources without proper credentials.",
        "risk": "Unauthorized access to admin panels, user data, and privileged operations.",
        "fix_steps": [
            "Implement authentication checks at the server-side for every protected endpoint",
            "Use established authentication frameworks (Passport.js, Spring Security)",
            "Avoid client-side authentication checks",
            "Implement proper session management with secure tokens",
            "Use multi-factor authentication for sensitive operations"
        ],
        "code_example": """# Python/Flask — middleware approach
@app.before_request
def require_auth():
    public = ['/login', '/register', '/health']
    if request.path not in public and not session.get('authenticated'):
        abort(401)""",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"]
    },
    
    "IDOR": {
        "description": "Insecure Direct Object Reference allows accessing other users' data by changing resource IDs.",
        "risk": "Data breach, unauthorized modification of other users' data.",
        "fix_steps": [
            "Always verify the authenticated user owns the requested resource",
            "Use indirect references (UUID instead of sequential IDs)",
            "Implement access control checks at the data layer",
            "Log and alert on unauthorized access attempts"
        ],
        "code_example": """# Vulnerable
@app.get("/api/orders/{order_id}")
def get_order(order_id):
    return db.orders.find(order_id)  # No ownership check!

# Fixed
@app.get("/api/orders/{order_id}")
def get_order(order_id, current_user=Depends(get_current_user)):
    order = db.orders.find(order_id)
    if order.user_id != current_user.id:
        raise HTTPException(403, "Access denied")
    return order""",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"]
    },

    "JWT Vulnerability": {
        "description": "JWT weaknesses allow forging or manipulating authentication tokens.",
        "risk": "Authentication bypass, privilege escalation, impersonation.",
        "fix_steps": [
            "Use strong algorithms (RS256 or ES256, never 'none')",
            "Validate algorithm in verification (don't accept alg from token)",
            "Set short expiration times with refresh tokens",
            "Store secrets securely, rotate regularly"
        ],
        "code_example": """# Python — secure JWT verification
import jwt
payload = jwt.decode(
    token, 
    public_key, 
    algorithms=["RS256"],  # Explicitly whitelist algorithm
    options={"require": ["exp", "iss"]}
)""",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"]
    },
    
    # ===== SERVER-SIDE =====
    "SSRF": {
        "description": "Server-Side Request Forgery allows the server to make requests to unintended locations.",
        "risk": "Access to internal services, cloud metadata theft (AWS IAM credentials), port scanning.",
        "fix_steps": [
            "Validate and whitelist allowed URLs/domains",
            "Block requests to internal/private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x)",
            "Disable unnecessary URL schemes (file://, gopher://, dict://)",
            "Use a dedicated HTTP client with strict redirect following",
            "Implement network-level segmentation"
        ],
        "code_example": """# Python — URL validation
from urllib.parse import urlparse
import ipaddress

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        return ip.is_global  # Block private IPs
    except ValueError:
        return parsed.hostname not in ('localhost', '127.0.0.1')""",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"]
    },

    "SSTI": {
        "description": "Server-Side Template Injection allows code execution through template engines.",
        "risk": "Remote code execution, full server compromise.",
        "fix_steps": [
            "Never pass user input directly to template engines",
            "Use sandboxed template environments",
            "Render user content as text, not template code",
            "Use logic-less templates (Mustache) where possible"
        ],
        "code_example": """# Vulnerable (Jinja2)
return render_template_string(user_input)

# Fixed
return render_template("page.html", content=user_input)""",
        "references": ["https://portswigger.net/research/server-side-template-injection"]
    },
    
    "LFI": {
        "description": "Local File Inclusion allows reading arbitrary files from the server.",
        "risk": "Source code disclosure, configuration file theft, credential exposure.",
        "fix_steps": [
            "Never use user input in file paths",
            "Use a whitelist of allowed files",
            "Implement chroot or containerization",
            "Remove path traversal sequences (../) after canonicalization"
        ],
        "code_example": """# Vulnerable
with open(f"/uploads/{filename}") as f: ...

# Fixed
import os
safe_path = os.path.realpath(os.path.join("/uploads", filename))
if not safe_path.startswith("/uploads/"):
    raise ValueError("Path traversal detected")""",
        "references": ["https://cwe.mitre.org/data/definitions/98.html"]
    },
    
    # ===== CLIENT-SIDE =====
    "CORS Misconfiguration": {
        "description": "Permissive CORS allows unauthorized cross-origin requests to read sensitive data.",
        "risk": "Data theft from authenticated sessions, CSRF-like attacks.",
        "fix_steps": [
            "Never reflect Origin header as Access-Control-Allow-Origin",
            "Whitelist specific trusted origins",
            "Avoid Access-Control-Allow-Credentials: true with wildcard origins",
            "Validate Origin header server-side"
        ],
        "code_example": """# Vulnerable
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true

# Fixed (Python/Flask)
from flask_cors import CORS
CORS(app, origins=["https://trusted-app.com"], supports_credentials=True)""",
        "references": ["https://portswigger.net/web-security/cors"]
    },
    
    "Clickjacking": {
        "description": "Clickjacking tricks users into clicking hidden elements through iframe overlays.",
        "risk": "Unintended actions (transfers, permission grants), credential theft.",
        "fix_steps": [
            "Set X-Frame-Options: DENY (or SAMEORIGIN)",
            "Implement Content-Security-Policy: frame-ancestors 'none'",
            "Use JavaScript frame-busting as defense-in-depth"
        ],
        "code_example": """# HTTP Headers
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'""",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"]
    },

    "Open Redirect": {
        "description": "Open redirect allows redirecting users to attacker-controlled sites.",
        "risk": "Phishing, credential theft, OAuth token theft.",
        "fix_steps": [
            "Validate redirect URLs against a whitelist of domains",
            "Use relative URLs instead of absolute URLs",
            "Don't pass redirect targets as user parameters"
        ],
        "code_example": """# Vulnerable
redirect(request.args.get('next'))

# Fixed (whitelist)
ALLOWED = ['/', '/dashboard', '/profile']
next_url = request.args.get('next', '/')
if next_url not in ALLOWED:
    next_url = '/'
redirect(next_url)""",
        "references": ["https://cwe.mitre.org/data/definitions/601.html"]
    },

    "CRLF Injection": {
        "description": "CRLF Injection allows injecting headers into HTTP responses.",
        "risk": "Session fixation, XSS via injected headers, cache poisoning.",
        "fix_steps": [
            "Strip CR (\\r) and LF (\\n) from user input used in headers",
            "Use framework-provided response header methods",
            "Validate and encode header values"
        ],
        "code_example": """# Validate header values
import re
def safe_header_value(value):
    return re.sub(r'[\\r\\n]', '', str(value))""",
        "references": ["https://cwe.mitre.org/data/definitions/93.html"]
    },
    
    # ===== MISCONFIG =====
    "Missing Security Headers": {
        "description": "Absence of security headers leaves the application vulnerable to various attacks.",
        "risk": "XSS, clickjacking, MIME sniffing, information leakage.",
        "fix_steps": [
            "Add Content-Security-Policy header",
            "Add X-Content-Type-Options: nosniff",
            "Add X-Frame-Options: DENY",
            "Add Strict-Transport-Security with long max-age",
            "Add Referrer-Policy: strict-origin-when-cross-origin"
        ],
        "code_example": """# Recommended Security Headers
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()""",
        "references": ["https://owasp.org/www-project-secure-headers/"]
    },

    "Directory Listing": {
        "description": "Directory listing exposes the file structure of the web server.",
        "risk": "Information disclosure, discovery of backup files, sensitive data exposure.",
        "fix_steps": [
            "Disable directory listing in web server configuration",
            "Add index files to all directories",
            "Use .htaccess or equivalent to deny access"
        ],
        "code_example": """# Apache
Options -Indexes

# Nginx
autoindex off;

# .htaccess
Options -Indexes""",
        "references": ["https://cwe.mitre.org/data/definitions/548.html"]
    },

    "Git Repository Exposed": {
        "description": "Exposed .git directory allows downloading the entire source code repository.",
        "risk": "Source code disclosure, credential theft, infrastructure mapping.",
        "fix_steps": [
            "Block access to .git directory in web server config",
            "Remove .git from deployment packages",
            "Use CI/CD pipelines that don't deploy VCS directories"
        ],
        "code_example": """# Nginx
location ~ /\\.git { deny all; }

# Apache  
<DirectoryMatch "\\.git">
    Require all denied
</DirectoryMatch>""",
        "references": ["https://cwe.mitre.org/data/definitions/538.html"]
    },

    "Backup File Found": {
        "description": "Backup files left on the server expose source code and configuration.",
        "risk": "Source code disclosure, database credentials, API keys.",
        "fix_steps": [
            "Remove all backup files from production",
            "Block common backup extensions in web server config",
            "Automate deployment to ensure clean deployments"
        ],
        "code_example": """# Nginx — block backup file access
location ~* \\.(bak|old|orig|save|swp|sql|tar\\.gz|zip)$ {
    deny all;
}""",
        "references": ["https://cwe.mitre.org/data/definitions/530.html"]
    },

    "SSL/TLS Weakness": {
        "description": "Weak SSL/TLS configuration allows potential interception of encrypted traffic.",
        "risk": "Man-in-the-middle attacks, credential interception.",
        "fix_steps": [
            "Disable TLS 1.0 and TLS 1.1",
            "Use strong cipher suites (AES-GCM, ChaCha20)",
            "Enable HSTS with long max-age",
            "Regularly renew certificates"
        ],
        "code_example": """# Nginx SSL Config
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers on;
add_header Strict-Transport-Security "max-age=31536000" always;""",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cheat_Sheet.html"]
    },
}


def get_remediation(finding_type):
    """Get remediation guide for a finding type using fuzzy matching.
    
    Returns dict with: description, risk, fix_steps, code_example, references
    Or a generic guide if no specific match is found.
    """
    # Exact match
    if finding_type in REMEDIATION_DB:
        return REMEDIATION_DB[finding_type]
    
    # Fuzzy match
    ftype_lower = finding_type.lower()
    for key, guide in REMEDIATION_DB.items():
        if key.lower() in ftype_lower or ftype_lower in key.lower():
            return guide
    
    # Keyword fallback
    keyword_map = {
        "sql": "SQL Injection",
        "xss": "Cross-Site Scripting (Reflected)",
        "command": "Command Injection",
        "rce": "Command Injection",
        "ssrf": "SSRF",
        "ssti": "SSTI",
        "lfi": "LFI",
        "traversal": "LFI",
        "cors": "CORS Misconfiguration",
        "redirect": "Open Redirect",
        "crlf": "CRLF Injection",
        "click": "Clickjacking",
        "header": "Missing Security Headers",
        "jwt": "JWT Vulnerability",
        "idor": "IDOR",
        "auth": "Authentication Bypass",
        "nosql": "NoSQL Injection",
        "git": "Git Repository Exposed",
        "backup": "Backup File Found",
        "ssl": "SSL/TLS Weakness",
        "tls": "SSL/TLS Weakness",
        "directory": "Directory Listing",
        "dom": "DOM XSS",
    }
    
    for kw, db_key in keyword_map.items():
        if kw in ftype_lower and db_key in REMEDIATION_DB:
            return REMEDIATION_DB[db_key]
    
    # Generic fallback
    return {
        "description": f"A security vulnerability of type '{finding_type}' was detected.",
        "risk": "Depends on the specific vulnerability context and exploitability.",
        "fix_steps": [
            "Review the vulnerability details and evidence carefully",
            "Consult OWASP guidelines for the specific vulnerability class",
            "Apply input validation and output encoding where applicable",
            "Implement defense-in-depth measures",
            "Retest after applying fixes"
        ],
        "code_example": "# Refer to OWASP Cheat Sheets for specific remediation code.",
        "references": [
            "https://cheatsheetseries.owasp.org/",
            "https://cwe.mitre.org/"
        ]
    }
