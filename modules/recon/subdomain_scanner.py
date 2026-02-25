import aiohttp
import asyncio
from urllib.parse import urlparse

async def query_crtsh(domain, session):
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        async with session.get(url, timeout=10, ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for sub in name_value.split('\n'):
                        sub = sub.strip().lower()
                        if sub and not sub.startswith('*') and domain in sub:
                            subdomains.add(sub)
    except Exception as e:
        print(f"[!] Subdomain Scan Error (crt.sh): {e}")
    return list(subdomains)

async def check_alive(session, sub, proto="https"):
    target = f"{proto}://{sub}"
    try:
        async with session.get(target, timeout=3, ssl=False) as resp:
            return sub, resp.status
    except Exception:
        return sub, None

async def verify_subdomains(subdomains, session=None):
    alive = []
    
    local_session = False
    if session is None:
        session = aiohttp.ClientSession()
        local_session = True
        
    try:
        tasks = [check_alive(session, sub) for sub in subdomains]
        results = await asyncio.gather(*tasks)
        
        for sub, status in results:
            if status:
                alive.append(f"{sub} (Status: {status})")
    finally:
        if local_session:
            await session.close()
            
    return alive

async def run_subdomain_scan(target_url, log_callback=None, session=None):
    findings = []
    parsed = urlparse(target_url)
    domain = parsed.netloc.split(':')[0]
    
    if domain.startswith("www."):
        domain = domain[4:]
        
    if log_callback: log_callback(f"🔭 Enumerating Subdomains for {domain}...")
    
    local_session = False
    if session is None:
        session = aiohttp.ClientSession()
        local_session = True
        
    try:
        subs = await query_crtsh(domain, session)
        
        if subs:
            if log_callback: log_callback(f"   Shape found {len(subs)} potential subdomains from Certificates.")
            
            findings.append({
                "type": "Subdomain Enumeration",
                "severity": "Info",
                "detail": f"Found {len(subs)} subdomains via Certificate Transparency.",
                "evidence": "\n".join(subs[:50]), 
                "exploit_data": {"subdomains": subs}
            })
    finally:
        if local_session:
            await session.close()
            
    return findings
