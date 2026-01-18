import aiohttp
import asyncio

# ลายเซ็นของเทคโนโลยีต่างๆ
TECH_SIGNATURES = {
    # CMS
    "WordPress": ["wp-content", "wp-includes", "wordpress", "wp-json"],
    "Joomla": ["joomla", "com_content"],
    "Drupal": ["drupal", "jquery.once.js"],
    "Magento": ["mage/cookies", "static/_requirejs"],
    "Shopify": ["myshopify.com"],
    
    # Frameworks (Backend)
    "Laravel": ["laravel_session", "XSRF-TOKEN", "_token"],
    "Django": ["csrftoken", "__guarded"],
    "Spring Boot": ["X-Application-Context", "Whitelabel Error Page"],
    "Flask": ["Werkzeug"],
    "ASP.NET": ["ASP.NET_SessionId", "__VIEWSTATE", "X-AspNet-Version"],
    "Ruby on Rails": ["X-Runtime", "authenticity_token"],
    "Node.js": ["X-Powered-By: Express", "node_modules"],
    "PHP": ["PHPSESSID", "X-Powered-By: PHP"],
    
    # Frontend/JS
    "React": ["react-dom", "react-root", "data-reactid"],
    "Vue.js": ["vue-server-renderer", "data-v-"],
    "Angular": ["ng-version", "ng-content"],
    "Svelte": ["svelte-"],
    "jQuery": ["jquery"],
    "Bootstrap": ["bootstrap"],
    "Tailwind": ["tailwind"],
    
    # Servers/Proxies
    "Nginx": ["nginx"],
    "Apache": ["apache"],
    "IIS": ["Microsoft-IIS"],
    "Cloudflare": ["cf-ray", "__cfduid", "cf_clearance"],
    "AWS": ["AWSALB", "AWSALBCORS"],
    "Envoy": ["server: envoy"]
}

async def detect_tech(session, url):
    findings = []
    detected = []
    
    try:
        async with session.get(url, timeout=5, ssl=False) as resp:
            headers = str(resp.headers).lower()
            text = (await resp.text()).lower()
            
            # 1. Check Headers
            if "server" in resp.headers:
                server = resp.headers["Server"]
                detected.append(f"Server: {server}")
                
            if "x-powered-by" in resp.headers:
                powered = resp.headers["X-Powered-By"]
                detected.append(f"Powered-By: {powered}")
            
            # 2. Check HTML/Cookies Signature
            for tech, keywords in TECH_SIGNATURES.items():
                for kw in keywords:
                    if kw.lower() in text or kw.lower() in headers:
                        if tech not in detected:
                            detected.append(tech)
                        break
                        
            if detected:
                findings.append({
                    "type": "Technology Stack",
                    "severity": "Info",
                    "detail": f"Detected technologies: {', '.join(detected)}",
                    "evidence": str(detected)
                })
                
    except:
        pass
        
    return findings

async def run_tech_detect(target_url, log_callback=None, headers=None):
    findings = []
    if log_callback: log_callback(f"🕵️ Fingerprinting Technology Stack...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        findings = await detect_tech(session, target_url)
        
    return findings