import random
import asyncio
import time

# List of modern User-Agents to rotate
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
]

# Proxy list placeholder (In future, load from file)
PROXIES = [] 

class EvasionManager:
    def __init__(self, use_jitter=True, use_proxy=False, proxy_url=None):
        self.use_jitter = use_jitter
        self.use_proxy = use_proxy or bool(proxy_url)
        self.current_ua = random.choice(USER_AGENTS)
        self.proxy_url = proxy_url
        self.extra_headers = {}  # [FIX] Persistent headers (auth, kill_chain enrichment)
        
        # Load proxy from config if not specified
        if not self.proxy_url:
            try:
                from core import config as app_config
                if app_config.get("proxy.enabled", False):
                    self.proxy_url = app_config.get("proxy.url", "")
                    self.use_proxy = bool(self.proxy_url)
            except Exception:
                pass

    def get_waf_bypass_headers(self):
        """ Generates headers to confuse WAFs regarding IP origin """
        spoof_ip = f"127.0.0.{random.randint(1, 255)}" if random.random() > 0.5 else f"192.168.{random.randint(0, 255)}.{random.randint(1, 255)}"
        
        headers = {
            "X-Forwarded-For": spoof_ip,
            "X-Originating-IP": spoof_ip,
            "X-Remote-IP": spoof_ip,
            "X-Remote-Addr": spoof_ip,
            "X-Client-IP": spoof_ip,
            "X-Host": spoof_ip,
            "X-Forwared-Host": spoof_ip,
        }
        return headers

    def get_headers(self):
        """ Returns headers with rotated User-Agent, WAF bypass headers, and any extra persistent headers """
        # Rotate UA
        if random.random() > 0.8:
            self.current_ua = random.choice(USER_AGENTS)
            
        headers = {
            "User-Agent": self.current_ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        
        # Merge WAF Bypass Headers
        headers.update(self.get_waf_bypass_headers())
        
        # [FIX] Merge persistent extra headers (auth bearer, kill_chain tokens, etc.)
        if self.extra_headers:
            headers.update(self.extra_headers)
        
        return headers

    def encode_payload(self, payload, technique="auto"):
        """ 
        Obfuscates payloads to bypass filters.
        Techniques: 'url', 'double_url', 'null', 'comment', 'case', 'auto'
        """
        if technique == "auto":
            technique = random.choice(['url', 'double_url', 'comment', 'case'])
            
        if technique == 'url':
            return "".join(f"%{ord(c):02x}" for c in payload)
            
        elif technique == 'double_url':
            # Encode % as %25
            encoded = "".join(f"%{ord(c):02x}" for c in payload)
            return "".join(f"%{ord(c):02x}" for c in encoded)
            
        elif technique == 'null':
            # Inject null bytes before dangerous chars
            return payload.replace("'", "%00'").replace('"', '%00"')
            
        elif technique == 'comment':
            # SQLi specific: REPLACE spaces with comments
            return payload.replace(" ", "/**/")
            
        elif technique == 'case':
            # Random toggle case
            return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
            
        return payload

    def get_proxy(self):
        """ Returns a proxy URL if configured """
        if self.use_proxy and self.proxy_url:
            return self.proxy_url
        if self.use_proxy and PROXIES:
            return random.choice(PROXIES)
        return None

    async def sleep_jitter(self):
        """ Smart Jitter: Random delay to act like a human """
        if self.use_jitter:
            # Delay between 0.5s to 2.5s
            delay = random.uniform(0.5, 2.5)
            await asyncio.sleep(delay)

    def mutate_request(self, params):
        """ 
        Applies HPP (HTTP Parameter Pollution) and other semantic evasions to parameters. 
        Input: dict of params
        Output: dict of mutated params (may contain lists for HPP)
        """
        mutated = {}
        for k, v in params.items():
            # 1. Parameter Case Toggling (id -> Id)
            if random.random() > 0.7:
                k = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in k)
            
            # 2. HPP: Duplicate Parameter with Junk
            # (id=1 -> id=1&id=999) - WAF might inspect the second one and ignore the first (or vice versa)
            if random.random() > 0.8:
                junk = str(random.randint(1000, 9999))
                # Note: aiohttp handles list values as multiple params
                mutated[k] = [v, junk] if random.random() > 0.5 else [junk, v]
            else:
                mutated[k] = v
                
        # 3. Add Random Junk Parameter
        if random.random() > 0.5:
            junk_key = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=5))
            mutated[junk_key] = str(random.randint(1, 100))
            
        return mutated