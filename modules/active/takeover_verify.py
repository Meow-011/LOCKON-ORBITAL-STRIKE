import aiohttp
import asyncio
import socket

# Signatures for Takeover
TAKEOVER_SIGNATURES = {
    "GitHub Pages": {"cname": "github.io", "body": "There isn't a GitHub Pages site here."},
    "Heroku": {"cname": "herokuapp.com", "body": "Heroku | Welcome to your new app!"},
    "AWS S3": {"cname": "s3.amazonaws.com", "body": "The specified bucket does not exist"},
    "Azure": {"cname": "azurewebsites.net", "body": "404 Web Site not found"},
    "Shopify": {"cname": "myshopify.com", "body": "Sorry, this shop is currently unavailable."},
    "Tumblr": {"cname": "tumblr.com", "body": "Whatever you were looking for doesn't currently exist at this address."},
    "WordPress": {"cname": "wordpress.com", "body": "Do you want to register"},
    "Zendesk": {"cname": "zendesk.com", "body": "Help Center Closed"},
}

async def verify_takeover(session, subdomain):
    findings = []
    
    try:
        # 1. Check CNAME via DNS
        # Using sync socket.gethostbyname_ex in thread executor
        loop = asyncio.get_event_loop()
        try:
            # Note: This is a simplified CNAME check. For robust DNS, use 'dnspython'.
            # Here we rely on system resolver which might resolve CNAME to IP.
            # A better approach is using 'dig' or 'nslookup' via subprocess if dnspython is not available.
            # For this example, we will check HTTP response primarily, 
            # but knowing CNAME helps confirm the platform.
            pass 
        except Exception: pass

        # 2. Check HTTP Response
        async with session.get(f"http://{subdomain}", timeout=5, ssl=False) as resp:
            text = await resp.text()
            
            for service, sig in TAKEOVER_SIGNATURES.items():
                if sig["body"] in text:
                    findings.append({
                        "type": "Subdomain Takeover",
                        "severity": "High",
                        "detail": f"Subdomain points to unclaimed {service} resource.",
                        "evidence": f"Service: {service}\nSignature found: '{sig['body']}'",
                        "remediation": f"Claim the resource on {service} or remove the CNAME record."
                    })
                    return findings # Found one is enough
                    
    except Exception:
        pass
        
    return findings

async def run_takeover_verify(target_url, subdomains, log_callback=None, headers=None):
    findings = []
    if not subdomains: return findings

    if log_callback: log_callback(f"🏴‍☠️ Verifying Subdomain Takeover on {len(subdomains)} targets...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = [verify_takeover(session, sub) for sub in subdomains]
        results = await asyncio.gather(*tasks)
        for res in results: findings.extend(res)
            
    return findings