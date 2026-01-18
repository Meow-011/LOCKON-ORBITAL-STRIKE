import asyncio
import re
from urllib.parse import urlparse, urljoin
from playwright.async_api import async_playwright

# Ignore these file extensions
IGNORED_EXT = (
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.js', 
    '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', 
    '.pdf', '.doc', '.docx', '.zip', '.tar', '.gz'
)

async def crawl_dynamic(start_url, max_pages=20, headless=True, log_callback=None, headers=None):
    """
    Crawls a website using Playwright to handle JavaScript-heavy sites (SPA).
    Returns: internal_urls, param_urls, external_urls
    """
    visited = set()
    queue = [start_url]
    
    internal_urls = set()
    param_urls = set()
    external_urls = set()
    
    domain = urlparse(start_url).netloc
    
    if log_callback: log_callback(f"🕸️ Starting Dynamic Crawler (Playwright) on {start_url}...")
    
    async with async_playwright() as p:
        # Launch Browser
        browser = await p.chromium.launch(headless=headless)
        
        # Prepare Context Options (Evasion)
        context_options = {"ignore_https_errors": True}
        if headers:
            # Extract UA separate from other headers
            ua = headers.get("User-Agent", "Mozilla/5.0")
            other_headers = {k: v for k, v in headers.items() if k.lower() != "user-agent"}
            
            context_options["user_agent"] = ua
            context_options["extra_http_headers"] = other_headers
            
        # Create context
        context = await browser.new_context(**context_options)
        page = await context.new_page()
        
        try:
            while queue and len(visited) < max_pages:
                url = queue.pop(0)
                if url in visited: continue
                
                visited.add(url)
                internal_urls.add(url)
                if "?" in url: param_urls.add(url)
                
                try:
                    if log_callback: log_callback(f"  > Rendering: {url}")
                    
                    # Navigate and wait for network idle (to let JS load)
                    response = await page.goto(url, wait_until="networkidle", timeout=15000)
                    
                    # Handling non-HTML responses
                    content_type = response.headers.get("content-type", "")
                    if "text/html" not in content_type:
                        continue
                    
                    # Extract Links using Evaluate (runs in browser context)
                    # Getting all hrefs from <a> tags and action from <form>
                    links = await page.evaluate("""() => {
                        const anchors = Array.from(document.querySelectorAll('a'));
                        const forms = Array.from(document.querySelectorAll('form'));
                        return {
                            hrefs: anchors.map(a => a.href),
                            actions: forms.map(f => f.action)
                        }
                    }""")
                    
                    all_candidates = links['hrefs'] + links['actions']
                    
                    for link in all_candidates:
                        if not link: continue
                        
                        # Remove #hash
                        link = link.split('#')[0]
                        if not link: continue
                        
                        parsed = urlparse(link)
                        
                        # Filter Extensions
                        if parsed.path.lower().endswith(IGNORED_EXT):
                            continue
                            
                        # Internal vs External
                        if parsed.netloc == domain or parsed.netloc == "":
                            if link not in visited and link not in queue:
                                    queue.append(link)
                        else:
                            if link.startswith("http"):
                                    external_urls.add(link)
                                    
                except Exception as e:
                    # if log_callback: log_callback(f"    [!] Error crawling {url}: {e}")
                    pass
        finally:
            await browser.close()
        
    if log_callback:
        log_callback(f"✅ Dynamic Crawl Complete: {len(internal_urls)} Internal, {len(external_urls)} External.")
        
    return list(internal_urls), list(param_urls), list(external_urls)
