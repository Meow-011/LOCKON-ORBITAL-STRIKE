import threading 
import asyncio
import time
import os
import aiohttp
import random

# Native Modules
from modules.active.auth_security import run_auth_security_scan
from modules.active.injection import run_safe_sql_injection
from modules.active.xss import run_xss_scan
from modules.recon.directory_brute import run_directory_scan
from modules.active.lfi import run_lfi_scan
from modules.active.cors import run_cors_scan
from modules.active.redirect import run_redirect_scan
from modules.active.secrets import run_secret_scan
from modules.recon.crawler_dynamic import crawl_dynamic
from modules.active.clickjacking import run_clickjacking_scan
from modules.recon.tech_detect import run_tech_detect
from modules.recon.waf import run_waf_scan
from modules.recon.ssl_checker import run_ssl_scan
from modules.recon.info_extract import run_info_extract
from modules.active.cms_scanner import run_cms_scan
from modules.recon.broken_links import run_broken_link_scan
from modules.active.proto_pollution import run_proto_pollution_scan
from modules.recon.http_methods import run_http_method_scan
from modules.active.backup_killer import run_backup_scan
from modules.recon.csp_analyzer import run_csp_analyze
from modules.active.git_extractor import run_git_extractor
from modules.active.jwt_breaker import run_jwt_scan
from modules.active.admin_brute import run_admin_brute
from modules.active.idor import run_idor_scan
from modules.active.error_exposure import run_error_exposure_scan
from modules.active.smuggling_verify import run_smuggling_verify
from modules.active.param_miner import run_param_miner
try:
    from modules.active.cve_sniper import run_cve_scan
except ImportError as e:
    print(f"❌ CRITICAL IMPORT ERROR: {e}")
    import sys, os
    print(f"   📂 CWD: {os.getcwd()}")
    print(f"   🐍 Sys.path: {sys.path}")
    # Fallback to prevent crash
    async def run_cve_scan(*args, **kwargs):
        print("   ⚠️ CVE Sniper disabled due to import error.")
        return []
from modules.active.ssti import run_ssti_scan
from modules.active.host_header import run_host_header_scan
from modules.recon.port_scanner import run_native_port_scan
from modules.active.bucket_looter import run_bucket_looter
from modules.active.auth_bypass import run_auth_bypass
from modules.active.upload_rce import run_upload_scan
from modules.active.crlf_injector import run_crlf_scan
from modules.active.nosql_injection import run_nosql_scan
from modules.active.ldap_injection import run_ldap_scan
from modules.active.os_cmd import run_os_command_scan
from modules.active.ssrf import run_ssrf_scan
from modules.recon.osint_hunter import run_osint_scan
from modules.active.graphql import run_graphql_scan

from core.database import init_db, save_scan_result


from core.evasion import EvasionManager
from core.reporter import generate_html_report
from core.domino import ChainReactor

try:
    from modules.recon.red_team import run_port_scan, run_subdomain_enum, run_nuclei_scan
except ImportError:
    async def run_port_scan(*args): return []
    async def run_subdomain_enum(*args): return []
    async def run_nuclei_scan(*args): return []

class ScannerThread(threading.Thread):
    def __init__(self, target, profile, log_callback, finding_callback, finish_callback, cookies=None, stealth_mode=False, modules_config=None, proxy_url=None, max_rps=20, scope_config=None, auth_config=None):
        super().__init__()
        self.target = target
        self.profile = profile
        self.log_callback = log_callback
        self.finding_callback = finding_callback
        self.finish_callback = finish_callback
        self.daemon = True 
        self.all_findings = []
        self.cookies = cookies 
        self._stop_event = threading.Event()
        self.loop = None
        self.modules_config = modules_config if modules_config else {}
        
        # [MOD] Project CORTEX Integration
        from core.cortex import CortexBrain
        self.cortex = CortexBrain()
        
        # [MOD] Project GHOST WRITER Integration
        from core.ghost_writer import GhostWriter
        self.ghost = GhostWriter()
        
        # [MOD] Phase 4: False Positive Validator
        from core.fp_validator import FPValidator
        self.fp_validator = FPValidator(log_callback=self.log_callback)
        
        # [MOD] Project DOMINO Integration
        self.domino = ChainReactor(self)
        
        # [MOD] Stealth Config
        use_jitter = True if stealth_mode else False
        self.evasion = EvasionManager(use_jitter=use_jitter, proxy_url=proxy_url)
        
        # [MOD] Rate Limiter (informational)
        self.max_rps = max(1, int(max_rps))
        
        # [MOD] Scope Manager
        from core.scope_manager import ScopeManager
        self.scope = ScopeManager(target)
        if scope_config and isinstance(scope_config, dict):
            self.scope.set_patterns(
                includes=scope_config.get('includes', ''),
                excludes=scope_config.get('excludes', '')
            )
            if self.scope.is_configured:
                self.log_callback(f"🎯 Scope Control ACTIVE — includes: {scope_config.get('includes', 'any')} | excludes: {scope_config.get('excludes', 'none')}")
        
        self.log_callback(f"⚡ Rate Limit: {self.max_rps} RPS")
        
        # [MOD] Auth Manager
        from core.auth_manager import AuthManager
        self.auth = AuthManager(log_callback=self.log_callback)
        if auth_config and isinstance(auth_config, dict):
            if auth_config.get('bearer_token'):
                self.auth.configure_bearer(auth_config['bearer_token'])
            elif auth_config.get('login_url'):
                self.auth.configure_form_login(
                    login_url=auth_config['login_url'],
                    username_field=auth_config.get('user_field', 'username'),
                    password_field=auth_config.get('pass_field', 'password'),
                    username=auth_config.get('username', ''),
                    password=auth_config.get('password', '')
                )
                if auth_config.get('validation_url'):
                    self.auth.configure_validation(auth_config['validation_url'])
        # Cookie auth (existing behavior, also handled by auth_manager)
        if cookies and not self.auth.is_authenticated:
            self.auth.configure_cookies(cookies)
        
        # [FIX #4] Inject auth tokens into evasion headers
        if auth_config and auth_config.get('bearer_token'):
            self.evasion.extra_headers['Authorization'] = f"Bearer {auth_config['bearer_token']}"
        
        init_db()
        
        # [STATS Engine]
        self.request_count = 0
        self.start_time = 0
        self.current_phase = "Initializing"
        self.total_steps = 1
        self.completed_steps = 0
        
    def get_stats(self):
        """Returns real-time scan statistics."""
        duration = time.time() - self.start_time if self.start_time > 0 else 0
        req_per_sec = int(self.request_count / duration) if duration > 1 else 0
        
        # [MOD] Calculate progress from module completion ratio
        progress = min(self.completed_steps / max(self.total_steps, 1), 1.0)
        
        return {
            "requests": self.request_count,
            "duration": int(duration),
            "pps": req_per_sec,
            "phase": self.current_phase,
            "progress": progress
        }

    def stop(self):
        self.log_callback("🛑 Abort signal received. Stopping services...")
        self._stop_event.set()

    def _step_done(self, name=""):
        """Mark a scan step as completed and update progress."""
        self.completed_steps += 1
        if name:
            self.current_phase = name

    async def pre_flight_check(self):
        self.log_callback(f"📡 Pre-flight check: Pinging {self.target}...")
        try:
            headers = self.evasion.get_headers()
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(self.target, timeout=10, ssl=False) as resp:
                    self.log_callback(f"✅ Target is ALIVE (Status: {resp.status})")
                    return True
        except Exception as e:
            self.log_callback(f"❌ Target Unreachable: {e}")
            self.log_callback("⚠️ Scan aborted due to connection failure.")
            return False
            
    def inc_req(self, count=1):
        self.request_count += count

    def run_async_process(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        # [FIX] Pre-import modules used inside loops to avoid repeated inline imports
        from modules.active.xxe_deep import run_xxe_scan
        from modules.active.deserialization import run_deserialization_scan
        from modules.active.race_condition import run_race_scan
        from modules.active.privesc import run_privesc_scan
        from modules.active.websocket_scanner import run_websocket_scan
        from modules.active.api_scanner import run_api_security_scan
        from modules.active.takeover import run_takeover_scan
        
        mode_msg = f"(Mode: {self.profile})"
        if self.cookies: mode_msg += " [Authenticated Mode 🍪]"
        
        self.log_callback(f"🚀 Initializing LOCKON Engine {mode_msg}")
        
        try:
            if not self.loop.run_until_complete(self.pre_flight_check()): return 
            if self._stop_event.is_set(): return
            
            # [FIX] Execute form-based login if configured
            if self.auth.method == "form_login":
                self.log_callback("🔐 Performing form-based login...")
                login_ok = self.loop.run_until_complete(self.auth.login())
                if login_ok:
                    # Inject captured session cookies into evasion headers
                    for k, v in self.auth.get_cookies_dict().items():
                        self.evasion.extra_headers.setdefault('Cookie', '')
                        if self.evasion.extra_headers['Cookie']:
                            self.evasion.extra_headers['Cookie'] += f'; {k}={v}'
                        else:
                            self.evasion.extra_headers['Cookie'] = f'{k}={v}'
            
            # [MOD] Modular Config Helpers
            cfg = self.modules_config
            any_web = any([cfg.get('sqli'), cfg.get('xss'), cfg.get('nosql'), cfg.get('rce'), cfg.get('cve'), cfg.get('auth'), cfg.get('leak')])
            
            # [FIX] Default scope variables to prevent NameError
            all_urls = []
            param_urls = []
            external_urls = []
            
            # [MOD] Calculate total steps for accurate progress
            steps = 2  # Phase 0 infra + finalize
            if any_web or self.profile in ["Full Scan", "Quick Scan"]: steps += 1  # infra scans
            if cfg.get('cloud'): steps += 1
            if cfg.get('leak'): steps += 1
            if cfg.get('cve') or self.profile == "Full Scan": steps += 1  # recon phase
            if cfg.get('recon'): steps += 1  # deep recon
            if cfg.get('cve'): steps += 1
            if cfg.get('rce'): steps += 1
            if cfg.get('auth'): steps += 1
            if cfg.get('api'): steps += 1
            if cfg.get('sqli') or cfg.get('xss') or cfg.get('nosql'): steps += 1  # injection loop
            steps += 3  # client-side + nuclei + ws_fuzzer
            self.total_steps = steps
            
            # --- PHASE 0: INFRASTRUCTURE ---
            
            # Helper: safe module runner (defined early so all phases can use it)
            def _safe_run(name, coro):
                """Run a module safely, catching exceptions so scan continues."""
                try:
                    result = self.loop.run_until_complete(coro)
                    self.process_findings(result)
                except Exception as e:
                    self.log_callback(f"⚠️ {name} failed: {e}")
            
            self.start_time = time.time()
            self.current_phase = "Infrastructure Analysis"
            
            # Always run basic recon if any web attack is selected or profile implies it
            if any_web or self.profile in ["Full Scan", "Quick Scan"]:
                self.log_callback("⚔️ Phase 0: Infrastructure Analysis...")
                
                # Port Scan (Light)
                _safe_run("Port Scan", run_native_port_scan(self.target, self.log_callback))
                
                # Crawling (Dynamic) - Essential for all web attacks
                if self._stop_event.is_set(): return
                self.log_callback("🕸️ Starting Dynamic Crawler (Playwright)...")
                try:
                    all_urls, param_urls, external_urls = self.loop.run_until_complete(crawl_dynamic(self.target, max_pages=15, log_callback=self.log_callback, headers=self.evasion.get_headers()))
                except Exception as e:
                    self.log_callback(f"⚠️ Dynamic Crawler failed: {e} — falling back to base URL only")
                    all_urls, param_urls, external_urls = [self.target], [], []
                
                # [FIX] Warn if crawler returned empty — injection scans will be limited
                if not param_urls:
                    self.log_callback("⚠️ No parameterized URLs found — injection scans limited to base URL")
                
                # Bucket Looter (Cloud)
                if cfg.get('cloud'):
                    _safe_run("Bucket Looter", run_bucket_looter(self.target, all_urls, self.log_callback, headers=self.evasion.get_headers()))
                    self._step_done("Cloud Recon")
                
                # Leaks (Git/Backup)
                if cfg.get('leak'):
                    _safe_run("Error Exposure", run_error_exposure_scan(self.target, self.log_callback, headers=self.evasion.get_headers()))
                    _safe_run("Git Extractor", run_git_extractor(self.target, self.log_callback, headers=self.evasion.get_headers()))
                    _safe_run("Backup Scan", run_backup_scan(self.target, all_urls, self.log_callback, headers=self.evasion.get_headers()))
                    self._step_done("Leak Detection")

                # Information Disclosure & Secrets
                if self._stop_event.is_set(): return
                _safe_run("Info Extract", run_info_extract(self.target, all_urls, self.log_callback, headers=self.evasion.get_headers()))
                _safe_run("Secret Scan", run_secret_scan(self.target, all_urls, self.log_callback, headers=self.evasion.get_headers()))

                # Directory Brute Force
                if self._stop_event.is_set(): return
                _safe_run("Directory Brute", run_directory_scan(self.target, self.log_callback, headers=self.evasion.get_headers()))

                # Broken Links
                _safe_run("Broken Links", run_broken_link_scan(self.target, external_urls, self.log_callback, headers=self.evasion.get_headers()))
                self._step_done("Infrastructure Analysis")

            # --- PHASE 1: RECON ---
            self._step_done("Reconnaissance")
            if self._stop_event.is_set(): return
            
            # Expanded Recon for certain modes
            if cfg.get('cve') or self.profile == "Full Scan":
                self.log_callback("🔍 Phase 1: Advanced Reconnaissance...")
                self.cortex.sleep(self._stop_event)
                
                _safe_run("Tech Detect", run_tech_detect(self.target, self.log_callback, headers=self.evasion.get_headers()))
                _safe_run("WAF Detect", run_waf_scan(self.target, self.log_callback, headers=self.evasion.get_headers()))
                _safe_run("SSL Analysis", run_ssl_scan(self.target, self.log_callback))
                _safe_run("CMS Detect", run_cms_scan(self.target, self.log_callback, headers=self.evasion.get_headers()))
                _safe_run("CSP Analysis", run_csp_analyze(self.target, self.log_callback, headers=self.evasion.get_headers()))
                _safe_run("HTTP Methods", run_http_method_scan(self.target, self.log_callback, headers=self.evasion.get_headers()))
                _safe_run("OSINT", run_osint_scan(self.target, all_urls, self.log_callback))

            # [KILL CHAIN] Upgrade Headers if tokens were found
            from modules.chain.kill_chain import kill_chain
            current_headers = self.evasion.get_headers()
            upgraded_headers = kill_chain.enrich_headers(current_headers)
            # Merge kill_chain tokens into evasion's persistent extra_headers
            for k, v in upgraded_headers.items():
                if k not in current_headers or current_headers[k] != v:
                    self.evasion.extra_headers[k] = v
            
            # --- PHASE 2: DEEP SCANNING ---
            self._step_done("Vulnerability Analysis")
            if self._stop_event.is_set(): return
            
            # [DEEP RECON] Protocol Shadow
            if cfg.get('recon'):
                self.log_callback("🌑 Utilizing Subfinder for Deep Reconnaissance...")
                subs = self.loop.run_until_complete(run_subdomain_enum(self.target, self.log_callback))
                self.process_findings(subs)
                for s in subs:
                    sub_url = f"https://{s['detail']}"
                    if sub_url not in param_urls: 
                        param_urls.append(sub_url)
                self.log_callback(f"🌑 Deep Recon: Added {len(subs)} new subdomains to attack scope.")

                # Subdomain Takeover (Phase 16)
                self.log_callback("☁️ Checking for Subdomain Takeover (Cloud Resources)...")
                # Check main target
                _safe_run("Takeover (main)", run_takeover_scan(self.target, self.log_callback))
                # Check discovered subdomains (limit 5 for speed)
                for s in subs[:5]:
                    sub_chk = f"https://{s['detail']}"
                    _safe_run("Takeover (sub)", run_takeover_scan(sub_chk, self.log_callback))
                self._step_done("Deep Recon")

            targets_to_scan = param_urls if param_urls else [self.target]
            self.log_callback(f"🎯 Analysis Targets: {len(targets_to_scan)} URLs (Deep Scan)")
            
            # [MODULAR EXECUTION] — Each group wrapped in try/except for crash isolation
            
            # 1. CVE Sniper
            if cfg.get('cve'):
                _safe_run("CVE Sniper", run_cve_scan(self.target, self.log_callback, headers=self.evasion.get_headers()))
                self._step_done("CVE Scanning")
            
            # 2. RCE / Cmd Injection
            if cfg.get('rce'):
                _safe_run("OS Command Scan", run_os_command_scan(self.target, self.log_callback, headers=self.evasion.get_headers()))
                _safe_run("Upload RCE", run_upload_scan(self.target, all_urls, self.log_callback, headers=self.evasion.get_headers()))
                self._step_done("RCE Scanning")

            # 3. Auth / IDOR
            if cfg.get('auth'):
                _safe_run("Auth Security", run_auth_security_scan(self.target, self.log_callback, headers=self.evasion.get_headers()))
                if self.cookies:
                    _safe_run("IDOR", run_idor_scan(self.target, all_urls, cookies=self.cookies, log_callback=self.log_callback, headers=self.evasion.get_headers()))

            # 4. API Warfare (Spectre)
            if cfg.get('api'):
                _safe_run("API Security", run_api_security_scan(self.target, all_urls, self.log_callback, headers=self.evasion.get_headers(), cookies=self.cookies))
                _safe_run("GraphQL", run_graphql_scan(self.target, self.log_callback, headers=self.evasion.get_headers()))
                self._step_done("API Warfare")

            # 5. Auth Hardening: JWT + Admin Brute + Auth Bypass + Smuggling
            if cfg.get('auth'):
                _safe_run("JWT Breaker", run_jwt_scan(self.target, self.log_callback, headers=self.evasion.get_headers()))
                _safe_run("Admin Brute", run_admin_brute(self.target, all_urls, self.log_callback, headers=self.evasion.get_headers()))
                _safe_run("Auth Bypass", run_auth_bypass(self.target, all_urls, self.log_callback, headers=self.evasion.get_headers()))
                _safe_run("Smuggling", run_smuggling_verify(self.target, self.log_callback, headers=self.evasion.get_headers()))
                self._step_done("Auth Hardening")
            
            # [FIX #2] Scope enforcement — filter URLs before injection loop
            scoped_targets = [u for u in targets_to_scan if self.scope.is_in_scope(u)]
            if len(scoped_targets) < len(targets_to_scan):
                self.log_callback(f"🎯 Scope filter: {len(targets_to_scan)} → {len(scoped_targets)} URLs in scope")
            
            # Loop scan for Injection flaws
            for url in scoped_targets:
                if self._stop_event.is_set(): break
                
                # [PHASE 36] Project SILENT WHISPER (WebSocket)
                if url.startswith("ws://") or url.startswith("wss://"):
                    _safe_run("WebSocket", run_websocket_scan(url, self.log_callback))
                    continue # Skip standard HTTP checks
                
                # [PHASE 37] Project GLASS HOUSE (XXE)
                _safe_run("XXE Deep", run_xxe_scan(url, method="POST", headers=self.evasion.get_headers(), log_callback=self.log_callback))
                
                self.cortex.sleep(self._stop_event)
                
                # [PHASE 31] Cortex Context Awareness
                suggestions = self.cortex.analyze_attack_surface(url)
                if suggestions:
                    self.log_callback(f"🧠 CORTEX: Context Analysis for '{url}' suggests: {', '.join(suggestions)}")
                
                # SQLi
                if cfg.get('sqli'):
                    _safe_run("SQLi", run_safe_sql_injection(url, safe_mode=True, log_callback=self.log_callback, headers=self.evasion.get_headers(), stealth_mode=self.evasion.use_jitter))
                
                # XSS
                if cfg.get('xss'):
                    _safe_run("XSS", run_xss_scan(url, self.log_callback, headers=self.evasion.get_headers(), stealth_mode=self.evasion.use_jitter))
                
                # NoSQL
                if cfg.get('nosql'):
                    _safe_run("NoSQL", run_nosql_scan(url, self.log_callback, headers=self.evasion.get_headers()))

                # SSTI (Server-Side Template Injection)
                if cfg.get('rce'):
                    _safe_run("SSTI", run_ssti_scan(url, self.log_callback, headers=self.evasion.get_headers()))
                    _safe_run("SSRF", run_ssrf_scan(url, self.log_callback, headers=self.evasion.get_headers()))

                # LFI (Local File Inclusion)
                _safe_run("LFI", run_lfi_scan(url, self.log_callback, headers=self.evasion.get_headers()))

                # CRLF Injection
                _safe_run("CRLF", run_crlf_scan(url, self.log_callback, headers=self.evasion.get_headers()))

                # Open Redirect
                _safe_run("Redirect", run_redirect_scan(url, self.log_callback, headers=self.evasion.get_headers()))

                # Host Header Injection
                _safe_run("Host Header", run_host_header_scan(url, self.log_callback, headers=self.evasion.get_headers()))

                # LDAP Injection
                if cfg.get('sqli'):
                    _safe_run("LDAP", run_ldap_scan(url, self.log_callback, headers=self.evasion.get_headers()))

                # CORS Misconfiguration
                _safe_run("CORS", run_cors_scan(url, self.log_callback, headers=self.evasion.get_headers()))

                # Param Mining
                _safe_run("Param Miner", run_param_miner(url, self.log_callback, headers=self.evasion.get_headers()))

                # Prototype Pollution
                if cfg.get('xss') or cfg.get('rce'):
                    _safe_run("Proto Pollution", run_proto_pollution_scan(url, self.log_callback, headers=self.evasion.get_headers()))

                # Deserialization (Phase 12)
                if cfg.get('rce') or cfg.get('sqli'):
                    _safe_run("Deserialization", run_deserialization_scan(url, self.log_callback, headers=self.evasion.get_headers()))

                # Race Conditions (Phase 13)
                if cfg.get('auth') or cfg.get('rce'):
                    _safe_run("Race Condition", run_race_scan(url, self.log_callback, headers=self.evasion.get_headers()))

                # PrivEsc Mass Assignment (Phase 20)
                if cfg.get('auth'):
                    _safe_run("PrivEsc", run_privesc_scan(url, self.log_callback, headers=self.evasion.get_headers()))

            # Mark injection loop done
            if scoped_targets:
                self._step_done("Injection Scanning")

            # --- PHASE 3: CLIENT SIDE ---
            self._step_done("Client-Side Attacks")
            if self._stop_event.is_set(): return
            
            # XSS, ETC... (Existing)
            
            # Client Deep Dive (Phase 15)
            from modules.active.client_fuzzer import run_client_deep_scan
            _safe_run("Client Fuzzer", run_client_deep_scan(self.target, self.log_callback, headers=self.evasion.get_headers()))
            
            # DOM XSS (Phase 17) - Browser Based
            from modules.active.dom_xss import run_dom_xss_scan
            _safe_run("DOM XSS", run_dom_xss_scan(self.target, self.log_callback, headers=self.evasion.get_headers()))

            # Check JS files specifically?
            # We need to extract scripts first. Or just rely on whatever URLs are in 'all_urls'
            # (all_urls usually comes from the Spider, which includes .js files)
            
            # from modules.active.xss import run_xss_scan (Already imported)
            # ... existing XSS code ... (Actually I just append above it)
            if self.profile in ["Full Scan", "Quick Scan"]:
                self.log_callback("🎭 Phase 3: Client-Side Interaction...")
                _safe_run("Clickjacking", run_clickjacking_scan(self.target, self.log_callback))

            # --- PHASE: NUCLEI TEMPLATES ---
            if not self._stop_event.is_set():
                try:
                    from core.nuclei_runner import run_nuclei_templates
                    self.log_callback("🧬 Running Nuclei Template Engine...")
                    nuclei_findings = self.loop.run_until_complete(
                        run_nuclei_templates(self.target, self.log_callback, headers=self.evasion.get_headers())
                    )
                    self.process_findings(nuclei_findings)
                    self._step_done("Nuclei Templates")
                except Exception as e:
                    self.log_callback(f"⚠️ Nuclei templates skipped: {e}")

            # --- PHASE: WEBSOCKET FUZZER ---
            if not self._stop_event.is_set():
                try:
                    from modules.active.ws_fuzzer import run_ws_fuzzer
                    ws_findings = self.loop.run_until_complete(
                        run_ws_fuzzer(self.target, self.log_callback, headers=self.evasion.get_headers())
                    )
                    self.process_findings(ws_findings)
                    self._step_done("WebSocket Fuzzer")
                except Exception as e:
                    self.log_callback(f"⚠️ WS Fuzzer skipped: {e}")

            if not self._stop_event.is_set():
                self._step_done("Scan Completed")
                self.log_callback("✅ Scan Completed Successfully.")
            else:
                self.log_callback("🛑 Scan Terminated by User.")
            
            # Auto HTML Report (config-gated)
            try:
                from core import config as app_config
                if app_config.get("report.auto_generate", False):
                    self.log_callback("📄 Generating HTML Report...")
                    report_path = generate_html_report(self.target, self.all_findings)
                    self.log_callback(f"✨ Report saved to: {report_path}")
            except Exception:
                pass

            # [FIX #5] Save to Database — protected
            try:
                self.log_callback("💾 Saving scan history...")
                save_scan_result(self.target, self.profile, self.all_findings)
            except Exception as e:
                self.log_callback(f"⚠️ Failed to save scan history: {e}")

        except Exception as e:
            self.log_callback(f"❌ CRITICAL ERROR: {str(e)}")
            import traceback
            traceback.print_exc()
        
        finally:
            self.log_callback("🏁 All tasks finished.")
            if self.loop and not self.loop.is_closed():
                try:
                    # [FIX] Allow pending tasks (like aiohttp cleanup) to complete
                    self.loop.run_until_complete(asyncio.sleep(0.5))
                    self.loop.close()
                except Exception:
                    pass

    def process_findings(self, findings_list):
        if findings_list:
            # [FIX #3] Pre-import modules used in processing loop
            from modules.chain.kill_chain import kill_chain
            from core.taxonomy import TaxonomyMapper, get_cwe, get_owasp
            from core.cvss_calculator import get_cvss_for_finding
            from core.remediation_db import get_remediation
            
            self.all_findings.extend(findings_list)
            
            # [KILL CHAIN] Feed the Knowledge Base
            for f in findings_list:
                kill_chain.process_finding(f)
                
            for f in findings_list:
                finding_type = f.get('type', 'Unknown')
                
                # [TAXONOMY] Classify finding
                f['category'] = TaxonomyMapper.classify(finding_type)
                
                # [CVSS] Calculate CVSS 3.1 Base Score
                cvss_data = get_cvss_for_finding(finding_type)
                f['cvss_score'] = cvss_data['score']
                f['cvss_vector'] = cvss_data['vector']
                f['cvss_severity'] = cvss_data['severity']
                
                # [CWE/OWASP] Map to industry standards
                f['cwe'] = get_cwe(finding_type)
                f['owasp'] = get_owasp(finding_type)
                
                # [REMEDIATION] Attach detailed fix guide
                f['remediation_guide'] = get_remediation(finding_type)
                
                # [Phase 4] Confidence scoring
                try:
                    self.fp_validator.score_finding(f)
                except Exception:
                    f['confidence'] = 50
                    f['confidence_label'] = 'MEDIUM'
                
                # [FIX #6] Protect finding_callback from GUI exceptions
                try:
                    self.finding_callback(f)
                except Exception:
                    pass
                
                # [GHOST WRITER] Auto-PoC Generation for Confirmed Vulnerabilities
                if f.get('severity') in ['High', 'Critical']:
                    poc_path = self.ghost.generate_poc(f)
                    if poc_path:
                        f['poc_path'] = poc_path
                        self.log_callback(f"👻 Ghost Writer: Generated Exploit PoC -> {os.path.basename(poc_path)}")

            # [PHASE 39] Project DOMINO (Chain Reaction)
            domino_actions = self.domino.react(findings_list)
            for action in domino_actions:
                 self.log_callback(f"🎲 DOMINO Effect: Triggered Chain Reaction -> {action}")
            
            # Accurate request tracking
            self.inc_req(len(findings_list))

    def run(self):
        try:
            self.run_async_process()
        except Exception as e:
            self.log_callback(f"❌ THREAD ERROR: {str(e)}")
        finally:
            self.finish_callback()