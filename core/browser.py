import asyncio
try:
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

class BrowserManager:
    def __init__(self):
        self.playwright = None
        self.browser = None
    
    async def start(self):
        if not PLAYWRIGHT_AVAILABLE:
            return False
        if not self.playwright:
            self.playwright = await async_playwright().start()
        if not self.browser:
            # Headless = True by default
            try:
                self.browser = await self.playwright.chromium.launch(headless=True, args=['--no-sandbox'])
                return True
            except Exception as e:
                print(f"[BROWSER ERROR] Could not launch browser: {e}. Try 'playwright install'")
                return False

    async def stop(self):
        if self.browser:
            await self.browser.close()
            self.browser = None
        if self.playwright:
            await self.playwright.stop()
            self.playwright = None

    async def scan_dom_xss(self, url, payloads):
        """
        Navigates to URL with various payloads and waits for alert dialog.
        Returns: List of successful payloads
        """
        if not PLAYWRIGHT_AVAILABLE or not self.browser:
            return []
            
        successful_payloads = []
        
        # Reuse context for speed, but new page per payload to be safe
        context = await self.browser.new_context(ignore_https_errors=True)
        
        for payload in payloads:
            # Construct URL (Hash based for DOM XSS usually)
            # Or Query param if we suspect reflection into DOM source
            
            # Simple heuristic: Try Hash first (Source Sink XSS)
            # URL+#payload
            target = f"{url}#{payload}" 
            page = await context.new_page()
            
            xss_triggered = False
            
            # Handler for dialog (alert)
            async def handle_dialog(dialog):
                nonlocal xss_triggered
                # If we see our specific alert message, it's a confirmed HIT
                if "XSS" in dialog.message or "1" in dialog.message: 
                    xss_triggered = True
                await dialog.dismiss()

            page.on("dialog", handle_dialog)
            
            try:
                # Go to page
                await page.goto(target, timeout=5000, wait_until="domcontentloaded")
                # Wait a bit for JS to execute
                await page.wait_for_timeout(1000)
                
                if xss_triggered:
                    successful_payloads.append(payload)
                    
            except Exception:
                pass
            finally:
                await page.close()
                
            if successful_payloads: break # Stop after confirmation? Or find all. Let's stop to save time.
            
        await context.close()
        return successful_payloads

# Singleton
browser_manager = BrowserManager()
