import aiohttp
import asyncio
import re
from urllib.parse import urlparse

# --- PATTERNS ---
EMAIL_REGEX = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
PHONE_REGEX = r'(?:\+?66|0)[0-9]{2}[- ]?[0-9]{3}[- ]?[0-9]{4}'  # Simple TH/Intl phone
SOCIAL_DOMAINS = [
    "linkedin.com", "facebook.com", "twitter.com", "x.com", 
    "instagram.com", "github.com", "gitlab.com", "medium.com"
]

async def scan_page(session, url, findings, seen_emails):
    try:
        async with session.get(url, timeout=5, ssl=False) as resp:
            text = await resp.text()
            
            # 1. Email Harvesting
            emails = set(re.findall(EMAIL_REGEX, text))
            for email in emails:
                # Filter out garbage (images, fake emails)
                if email.lower() in seen_emails: continue
                if any(x in email.lower() for x in ['.png', '.jpg', '.gif', '.js', '.css', 'example.com']): continue
                
                seen_emails.add(email.lower())
                findings.append({
                    "type": "OSINT: Disclosed Email Address",
                    "severity": "Info",
                    "detail": f"Found email address: {email}",
                    "evidence": f"Source: {url}\nEmail: {email}",
                    "category": "Information Gathering"
                })
            
            # 2. Social Media Links
            for domain in SOCIAL_DOMAINS:
                if domain in text:
                    # Simple check, finer extraction is hard without heavy parsing
                    # Let's try to extract the specific link
                    matches = re.findall(r'(https?://(?:www\.)?' + re.escape(domain) + r'/[a-zA-Z0-9./_-]+)', text)
                    for link in matches:
                        findings.append({
                            "type": f"OSINT: Social Profile ({domain})",
                            "severity": "Info",
                            "detail": f"Found social media link: {link}",
                            "evidence": f"Source: {url}\nLink: {link}",
                            "category": "Information Gathering"
                        })
                        
            # 3. Phone Numbers (Risky, many false positives)
            phones = set(re.findall(PHONE_REGEX, text))
            for p in phones:
                 findings.append({
                    "type": "OSINT: Potential Phone Number",
                    "severity": "Info",
                    "detail": f"Found potential phone number: {p}",
                    "evidence": f"Source: {url}\nNumber: {p}",
                    "category": "Information Gathering"
                })

    except Exception:
        pass

async def run_osint_scan(target_url, crawled_urls, log_callback=None, headers=None):
    findings = []
    seen_emails = set()
    
    if log_callback: log_callback(f"🕵️‍♂️ Hunting for Person Intel (Emails, Socials)...")
    
    # Heuristic: Focus on Contact, About, Team, Staff pages
    keywords = ["contact", "about", "team", "staff", "people", "profile", "career", "job"]
    target_pages = [target_url] # Always scan home
    
    for u in crawled_urls:
        if any(k in u.lower() for k in keywords):
            target_pages.append(u)
            
    # Limit to avoid scanning 1000 pages again
    target_pages = list(set(target_pages))[:15]
    
    if not target_pages:
        if log_callback: log_callback("   No specific 'About/Contact' pages found. Scanning Homepage only.")
        target_pages = [target_url]

    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = []
        for url in target_pages:
            tasks.append(scan_page(session, url, findings, seen_emails))
        
        await asyncio.gather(*tasks)
        
    if log_callback:
        count = len(findings)
        if count > 0:
            log_callback(f"✅ OSINT Complete: Found {count} intel items.")
        else:
            log_callback(f"⚠️ OSINT Complete: No intel found (Clean target).")
            
    return findings
