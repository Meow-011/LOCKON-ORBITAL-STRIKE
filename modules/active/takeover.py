import aiohttp
import asyncio

# Signatures for "Dangling" services
# If these strings appear in the response, the subdomain is likely unclaimed.
TAKEOVER_SIGNATURES = {
    "AWS S3 Bucket": ["NoSuchBucket", "The specified bucket does not exist"],
    "GitHub Pages": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"],
    "Heroku": ["Heroku | No such app", "<title>No such app</title>"],
    "Azure": ["The specified container does not exist"],
    "Zendesk": ["Help Center Closed"],
    "Shopify": ["Sorry, this shop is currently unavailable"],
    "Tumblr": ["Whatever you were looking for doesn't currently exist at this address"],
    "WordPress": ["Do you want to register *.wordpress.com?"],
    "Ghost": ["The thing you were looking for is no longer here", "The page you looking for is not found"],
    "Cargo": ["If you're moving your domain away from Cargo you must make this configuration through your registrar's DNS control panel"],
    "Pantheon": ["404 Error - The specified site could not be found"],
    "Surge.sh": ["project not found"],
}

async def check_takeover(session, url):
    findings = []
    
    # Takeover usually happens on the root of the subdomain
    # We strip path to be sure (unless it's a specific resource takeover, but mostly it's whole domain)
    # Actually, let's just check the URL provided. If spider found 'sub.example.com/foo', we check 'sub.example.com/'
    
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        root_url = f"{parsed.scheme}://{parsed.netloc}/"
        
        async with session.get(root_url, timeout=5, ssl=False) as resp:
            text = await resp.text()
            
            for service, sigs in TAKEOVER_SIGNATURES.items():
                for sig in sigs:
                    if sig in text:
                        findings.append({
                            "type": f"Subdomain Takeover ({service})",
                            "severity": "Critical",
                            "detail": f"Subdomain {parsed.netloc} points to an unclaimed {service} resource.",
                            "evidence": f"Found signature: '{sig}' in response.",
                            "remediation": f"Claim the resource on {service} immediately or remove the DNS record."
                        })
                        return findings # Found one match is enough
    except:
        pass
        
    return findings

async def run_takeover_scan(target_url, log_callback=None, headers=None):
    findings = []
    # We run this check lightly.
    # Ideally should run only once per domain.
    # The caller (scanner.py) usually iterates unique URLs. 
    # Logic in scanner.py should deduplicate domains if possible, or we trust 'target_url' is distinct enough.
    
    if log_callback: pass # Too verbose to log every check, usually silent unless found
    
    async with aiohttp.ClientSession(headers=headers) as session:
        findings = await check_takeover(session, target_url)
        
    return findings
