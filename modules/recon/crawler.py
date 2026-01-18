import aiohttp
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

async def crawl_target(start_url, max_pages=30, log_callback=None):
    """
    Crawler V2: เก็บทั้ง Internal URLs และ External URLs
    """
    visited = set()
    queue = [start_url]
    
    internal_urls = set() # URL ภายใน (เอาไปสแกนช่องโหว่)
    param_urls = set()    # URL ที่มี Parameter (เอาไปยิง SQLi)
    external_urls = set() # URL ภายนอก (เอาไปเช็ค Broken Link)
    
    domain = urlparse(start_url).netloc
    
    if log_callback: log_callback(f"🕷️ Starting Spider on {start_url} (Max: {max_pages} pages)...")
    
    async with aiohttp.ClientSession() as session:
        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            if url in visited: continue
            
            visited.add(url)
            internal_urls.add(url)
            
            if "?" in url:
                param_urls.add(url)
            
            try:
                async with session.get(url, timeout=5, ssl=False) as resp:
                    # เช็คว่าเป็น HTML หรือไม่
                    if "text/html" not in resp.headers.get("Content-Type", ""):
                        continue
                        
                    html = await resp.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # หา <a> Tags
                    for link in soup.find_all('a', href=True):
                        full_url = urljoin(url, link['href'])
                        parsed = urlparse(full_url)
                        
                        # กรองไฟล์ที่ไม่ใช่เว็บเพจ
                        if full_url.endswith(('.png', '.jpg', '.css', '.js', '.pdf', '.woff', '.svg')):
                            continue

                        # แยกแยะ Internal vs External
                        if parsed.netloc == domain or parsed.netloc == "":
                            if full_url not in visited and full_url not in queue:
                                queue.append(full_url)
                        else:
                            # เป็น Link ภายนอก (เช่น facebook.com, cdn.com)
                            external_urls.add(full_url)
                                
                    # หา <form> action
                    for form in soup.find_all('form', action=True):
                         full_url = urljoin(url, form['action'])
                         if urlparse(full_url).netloc == domain:
                             internal_urls.add(full_url)
                             
            except Exception as e:
                pass
                
    if log_callback: 
        log_callback(f"✅ Spider stats: {len(internal_urls)} Internal, {len(external_urls)} External URLs.")
            
    return list(internal_urls), list(param_urls), list(external_urls)