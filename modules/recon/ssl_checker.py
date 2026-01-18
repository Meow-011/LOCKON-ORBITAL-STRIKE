import ssl
import socket
import asyncio
from urllib.parse import urlparse
from datetime import datetime

def check_weak_ciphers(hostname, port=443):
    """ Tries to connect using weak ciphers to see if server accepts them. """
    weak_findings = []
    
    # List of weak cipher strings to test
    # Note: Modern OpenSSL might not even support sending these, so this is "best effort"
    WEAK_CIPHER_SUITES = [
        ("NULL", "Null Cipher (No Encryption)"),
        ("ADH", "Anonymous Diffie-Hellman (No Auth)"),
        ("EXP", "Export Grade (Weak Keys)"),
        ("RC4", "RC4 (Obsolete/Insecure)"),
        ("DES", "DES (Obsolete/Insecure)"),
        ("MD5", "MD5 MAC (Weak)"),
    ]

    for cipher_str, issues in WEAK_CIPHER_SUITES:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                context.set_ciphers(cipher_str)
            except ssl.SSLError:
                # Local OpenSSL doesn't support this cipher, skip
                continue

            with socket.create_connection((hostname, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # If we got here, handshake succeeded with weak cipher!
                    cipher_used = ssock.cipher()
                    weak_findings.append({
                        "type": f"Weak SSL/TLS Cipher Supported ({cipher_str})",
                        "severity": "Medium", # or High depending on type
                        "detail": f"Server accepted weak cipher suite: {cipher_str} ({issues}).\nActual Cipher: {cipher_used[0]}",
                        "evidence": f"Cipher Suite: {cipher_str}",
                        "remediation": "Disable weak ciphers. Use modern TLS 1.2+ suites only."
                    })
        except:
            pass
            
    return weak_findings

def get_ssl_info_sync(hostname, port=443):
    findings = []
    
    # 1. Weak Cipher Check
    cipher_findings = check_weak_ciphers(hostname, port)
    findings.extend(cipher_findings)
    
    # 2. Basic Info & Expiration
    try:
        ctx = ssl.create_default_context() 
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE # Get cert even if invalid self-signed (we check validity separately below)
        
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True) # Binary first to be safe? No, let's use standard.
                # Re-do with default settings to get parsed cert if possible
                pass
                
    except: pass

    # Use standard validation attempt for expiration details
    try:
        # Standard Context (Verify=True to check trust store)
        # Note: If target is self-signed, this will fail SSLCertVerificationError, so we catch it.
        # But to get dates we might need unverified context if verified fails.
        
        # Strategy: Try unverified first to get Dates (always works), then check if Trusted (optional).
        ctx = ssl.create_default_context()
        ctx.check_hostname = False 
        ctx.verify_mode = ssl.CERT_NONE # Allow fetching cert to read dates
        
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Check Protocol Version (Best effort)
                ver = ssock.version()
                if ver in ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]:
                     findings.append({
                        "type": "Obsolete SSL/TLS Protocol",
                        "severity": "High",
                        "detail": f"Server supports obsolete protocol: {ver}",
                        "evidence": f"Protocol: {ver}",
                        "remediation": "Disable SSLv3, TLS 1.0, TLS 1.1. Enforce TLS 1.2 or 1.3."
                    })

                # Check Expiration
                not_after_str = cert['notAfter']
                expire_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_date - datetime.now()).days
                
                if days_left < 0:
                    findings.append({
                        "type": "SSL Certificate Expired",
                        "severity": "High",
                        "detail": f"Certificate expired on {expire_date.strftime('%Y-%m-%d')}.",
                        "evidence": f"NotAfter: {not_after_str}"
                    })
                elif days_left < 30:
                    findings.append({
                        "type": "SSL Certificate Expiring Soon",
                        "severity": "Low",
                        "detail": f"Certificate will expire in {days_left} days.",
                        "evidence": f"NotAfter: {not_after_str}"
                    })
                    
                # Check Issuer
                issuer = dict(x[0] for x in cert['issuer'])
                common_name = issuer.get('commonName', 'Unknown')
                findings.append({
                    "type": "SSL/TLS Info",
                    "severity": "Info",
                    "detail": f"Issuer: {common_name}, Expires: {days_left} days.",
                    "evidence": f"Serial: {cert.get('serialNumber')}"
                })
                
    except Exception as e:
        # If we can't even connect unverified, it's not HTTPS or down
        pass
        
    return findings

async def run_ssl_scan(target_url, log_callback=None):
    findings = []
    if not target_url.startswith("https"):
        return findings

    parsed = urlparse(target_url)
    hostname = parsed.netloc.split(":")[0]
    port = 443
    if ":" in parsed.netloc:
        try: port = int(parsed.netloc.split(":")[1])
        except: pass
        
    if log_callback: log_callback(f"🔒 Analyzing SSL/TLS Configuration for {hostname}...")
    
    # รัน Sync function ใน Thread แยก เพราะ socket เป็น blocking I/O
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, get_ssl_info_sync, hostname, port)
    
    if result:
        findings.extend(result)
        
    return findings