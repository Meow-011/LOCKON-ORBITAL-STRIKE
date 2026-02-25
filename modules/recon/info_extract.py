import aiohttp
import asyncio
import re
from urllib.parse import urlparse

# Regex Patterns
EMAIL_REGEX = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
PHONE_REGEX = r'\+?[\d\s-]{10,15}'
THAI_ID_REGEX = r'\b\d{13}\b' # Thai National ID
CREDIT_CARD_REGEX = r'\b(?:\d[ -]*?){13,16}\b' # Basic Visa/Mastercard pattern
SOCIAL_DOMAINS = ["facebook.com", "twitter.com", "linkedin.com", "instagram.com", "github.com"]

async def scan_page_info(session, url):
    findings = []
    pii_found = {"emails": set(), "phones": set(), "thai_ids": set(), "credit_cards": set(), "socials": set(), "metadata": []}
    
    try:
        # Determine if it's a file for metadata extraction
        is_doc = any(url.lower().endswith(ext) for ext in ['.pdf', '.docx', '.jpg', '.jpeg', '.png'])
        
        async with session.get(url, timeout=10, ssl=False) as resp:
            # Metadata Extraction (Binary)
            if is_doc and resp.status == 200:
                # Read first 8KB for metadata
                chunk = await resp.content.read(8192)
                
                # PDF Metadata (Basic ASCII Search)
                if url.endswith(".pdf"):
                    try:
                        # Search for /Title, /Author, /Creator
                        meta_patterns = [rb'/Title \((.*?)\)', rb'/Author \((.*?)\)', rb'/Creator \((.*?)\)', rb'/Producer \((.*?)\)']
                        for pattern in meta_patterns:
                            m = re.search(pattern, chunk)
                            if m:
                                pii_found["metadata"].append(f"PDF {pattern.split(b' ')[0].decode()}: {m.group(1).decode(errors='ignore')}")
                    except Exception: pass
                    
                # EXIF (Basic Search for Software/Make)
                if url.endswith((".jpg", ".jpeg")):
                     # Very naive string search for strict EXIF would need library
                     # Just look for common software tags
                     try:
                         if b"Adobe Photoshop" in chunk: pii_found["metadata"].append("EXIF: Processed with Adobe Photoshop")
                         if b"iPhone" in chunk: pii_found["metadata"].append("EXIF: Camera - iPhone")
                     except Exception: pass
                     
                return pii_found # Stop text scanning for binary files

            # Text Analysis (PII)
            text = await resp.text()
            
            # 1. Extract Emails
            found_emails = re.findall(EMAIL_REGEX, text)
            for email in found_emails:
                if not any(email.endswith(ext) for ext in ['.png', '.jpg', '.js', '.css', 'example.com']):
                    pii_found["emails"].add(email)
            
            # 2. Extract Phones
            found_phones = re.findall(PHONE_REGEX, text)
            for phone in found_phones:
                clean_phone = re.sub(r'\D', '', phone)
                if len(clean_phone) >= 9:
                    pii_found["phones"].add(phone.strip())

            # 3. Thai ID
            found_thai_ids = re.findall(THAI_ID_REGEX, text)
            for tid in found_thai_ids:
                 pii_found["thai_ids"].add(tid)

            # 4. Credit Cards
            found_ccs = re.findall(CREDIT_CARD_REGEX, text)
            for cc in found_ccs:
                 # Basic Luhn check could go here, but keep it fast
                 clean_cc = re.sub(r'\D', '', cc)
                 if len(clean_cc) >= 13:
                     pii_found["credit_cards"].add(clean_cc)

            # 5. Extract Social Links
            for domain in SOCIAL_DOMAINS:
                if domain in text:
                    pii_found["socials"].add(domain)

    except Exception:
        pass
        
    return pii_found

async def run_info_extract(target_url, crawled_urls, log_callback=None, headers=None):
    findings = []
    
    if not crawled_urls:
        return findings

    if log_callback: log_callback(f"📝 Mining PII (Emails/IDs/CC) & Metadata from {len(crawled_urls)} pages...")
    
    aggregated = {
        "emails": set(), "phones": set(), "thai_ids": set(), 
        "credit_cards": set(), "socials": set(), "metadata": []
    }

    async with aiohttp.ClientSession(headers=headers) as session:
        # Limit scan to 30 pages + any pdf/doc found
        targets = crawled_urls[:30] 
        # Add pdfs if in crawled list (but not in first 30)
        docs = [u for u in crawled_urls if u.endswith(('.pdf', '.docx'))][:5]
        targets.extend(docs)
        targets = list(set(targets))

        tasks = []
        for url in targets:
            tasks.append(scan_page_info(session, url))
        
        results = await asyncio.gather(*tasks)
        
        for res in results:
            aggregated["emails"].update(res["emails"])
            aggregated["phones"].update(res["phones"])
            aggregated["thai_ids"].update(res["thai_ids"])
            aggregated["credit_cards"].update(res["credit_cards"])
            aggregated["socials"].update(res["socials"])
            aggregated["metadata"].extend(res["metadata"])

    # Report Findings
    if aggregated["emails"]:
        findings.append({
            "type": "PII Disclosure (Emails)",
            "severity": "Low",
            "detail": f"Found {len(aggregated['emails'])} email addresses.",
            "evidence": ", ".join(list(aggregated['emails'])[:5])
        })
    
    if aggregated["phones"]:
        findings.append({
            "type": "PII Disclosure (Phones)",
            "severity": "Low",
            "detail": f"Found {len(aggregated['phones'])} phone numbers.",
            "evidence": ", ".join(list(aggregated['phones'])[:5])
        })

    if aggregated["thai_ids"]:
        findings.append({
            "type": "PII Disclosure (Thai National IDs)",
            "severity": "High",
            "detail": f"Found {len(aggregated['thai_ids'])} potential national IDs.",
            "evidence": ", ".join(list(aggregated['thai_ids'])[:3])
        })

    if aggregated["credit_cards"]:
        findings.append({
            "type": "Financial Data Exposure (Credit Cards)",
            "severity": "Critical",
            "detail": f"Found {len(aggregated['credit_cards'])} potential credit card numbers.",
            "evidence": "REDACTED (First 5: " + ", ".join([c[:4]+"..." for c in list(aggregated['credit_cards'])[:5]]) + ")"
        })

    if aggregated["metadata"]:
        findings.append({
            "type": "Metadata Exposure",
            "severity": "Info",
            "detail": f"Extracted metadata from documents/images.",
            "evidence": "\n".join(aggregated["metadata"][:10])
        })

    if log_callback:
        if aggregated["thai_ids"]: log_callback(f"   🆔 Found Thai IDs: {len(aggregated['thai_ids'])}")
        if aggregated["credit_cards"]: log_callback(f"   💳 Found Credit Cards: {len(aggregated['credit_cards'])}")
        if aggregated["metadata"]: log_callback(f"   📄 Extracted Metadata: {len(aggregated['metadata'])} items")

    return findings