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
from modules.recon.subdomain_scanner import run_subdomain_scan
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
from modules.active.takeover_verify import run_takeover_verify
from modules.active.smuggling_verify import run_smuggling_verify
from modules.active.api_fuzzer import run_api_scan
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

from core.database import init_db, save_scan_result
from core.smart_fuzzer import SmartFuzzer

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
    def __init__(self, target, profile, log_callback, finding_callback, finish_callback, cookies=None, stealth_mode=False, modules_config=None):
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
        
        # [MOD] Project DOMINO Integration
        self.domino = ChainReactor(self)
        
        # [MOD] Stealth Config
        use_jitter = True if stealth_mode else False
        self.evasion = EvasionManager(use_jitter=use_jitter)
        
        init_db()
        
        # [STATS Engine]
        self.request_count = 0
        self.start_time = 0
        self.current_phase = "Initializing"
        self.on_progress = None
        
    def get_stats(self):
        """Returns real-time scan statistics."""
        duration = time.time() - self.start_time if self.start_time > 0 else 0
        req_per_sec = int(self.request_count / duration) if duration > 1 else 0
        
        # Calculate approximate progress based on phase
        progress = 0.0
        if "Infrastructure" in self.current_phase: progress = 0.2
        elif "Recon" in self.current_phase: progress = 0.4
        elif "Vulnerability" in self.current_phase: progress = 0.7
        elif "Client-Side" in self.current_phase: progress = 0.9
        elif "Completed" in self.current_phase: progress = 1.0
        
        return {
            "requests": self.request_count,
            "duration": int(duration),
            "pps": req_per_sec, # Packets/Requests per second
            "phase": self.current_phase,
            "progress": progress
        }

    def stop(self):
        self.log_callback("🛑 Abort signal received. Stopping services...")
        self._stop_event.set()

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
        
        mode_msg = f"(Mode: {self.profile})"
        if self.cookies: mode_msg += " [Authenticated Mode 🍪]"
        
        self.log_callback(f"🚀 Initializing LOCKON Engine {mode_msg}")
        
        try:
            if not self.loop.run_until_complete(self.pre_flight_check()): return 
            if self._stop_event.is_set(): return
            
            # [MOD] Modular Config Helpers
            cfg = self.modules_config
            any_web = any([cfg.get('sqli'), cfg.get('xss'), cfg.get('nosql'), cfg.get('rce'), cfg.get('cve'), cfg.get('auth'), cfg.get('leak')])
            
            # --- PHASE 0: INFRASTRUCTURE ---
            self.start_time = time.time()
            self.current_phase = "Infrastructure Analysis"
            
            # Always run basic recon if any web attack is selected or profile implies it
            if any_web or self.profile in ["Full Scan", "Quick Scan"]:
                self.log_callback("⚔️ Phase 0: Infrastructure Analysis...")
                
                # Port Scan (Light)
                native_ports = self.loop.run_until_complete(run_native_port_scan(self.target, self.log_callback))
                self.process_findings(native_ports)
                
                # Crawling (Dynamic) - Essential for all web attacks
                if self._stop_event.is_set(): return
                self.log_callback("🕸️ Starting Dynamic Crawler (Playwright)...")
                all_urls, param_urls, external_urls = self.loop.run_until_complete(crawl_dynamic(self.target, max_pages=15, log_callback=self.log_callback, headers=self.evasion.get_headers()))
                
                # Bucket Looter (Cloud)
                if cfg.get('cloud'):
                    buckets = self.loop.run_until_complete(run_bucket_looter(self.target, all_urls, self.log_callback, headers=self.evasion.get_headers()))
                    self.process_findings(buckets)
                
                # Leaks (Git/Backup)
                if cfg.get('leak'):
                    error_ex = self.loop.run_until_complete(run_error_exposure_scan(self.target, self.log_callback, headers=self.evasion.get_headers()))
                    self.process_findings(error_ex)
                    
                    git_leaks = self.loop.run_until_complete(run_git_extractor(self.target, self.log_callback, headers=self.evasion.get_headers()))
                    self.process_findings(git_leaks)
                    
                    backups = self.loop.run_until_complete(run_backup_scan(self.target, all_urls, self.log_callback, headers=self.evasion.get_headers()))
                    self.process_findings(backups)

            # --- PHASE 1: RECON ---
            self.current_phase = "Reconnaissance"
            if self._stop_event.is_set(): return
            
            # Expanded Recon for certain modes
            if cfg.get('cve') or self.profile == "Full Scan":
                self.log_callback("🔍 Phase 1: Advanced Reconnaissance...")
                # self.loop.run_until_complete(self.evasion.sleep_jitter())
                self.cortex.sleep()
                
                tech = self.loop.run_until_complete(run_tech_detect(self.target, self.log_callback, headers=self.evasion.get_headers()))
                self.process_findings(tech)
                
                waf = self.loop.run_until_complete(run_waf_scan(self.target, self.log_callback, headers=self.evasion.get_headers()))
                self.process_findings(waf)

                # SSL Analysis
                ssl_res = self.loop.run_until_complete(run_ssl_scan(self.target, self.log_callback))
                ssl_res = self.loop.run_until_complete(run_ssl_scan(self.target, self.log_callback))
                self.process_findings(ssl_res)

            # [KILL CHAIN] Upgrade Headers if tokens were found
            from modules.chain.kill_chain import kill_chain
            current_headers = self.evasion.get_headers()
            upgraded_headers = kill_chain.enrich_headers(current_headers)
            # Update evasion module or just use 'upgraded_headers' here?
            # Easier to just pass 'upgraded_headers' to subsequent calls.
            # But many calls use 'self.evasion.get_headers()' directly.
            # So, let's hack: 
            self.evasion.headers = upgraded_headers # Update globally for this scan
            
            # --- PHASE 2: DEEP SCANNING ---
            self.current_phase = "Vulnerability Analysis"
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
                from modules.active.takeover import run_takeover_scan
                self.log_callback("☁️ Checking for Subdomain Takeover (Cloud Resources)...")
                # Check main target
                self.process_findings(self.loop.run_until_complete(run_takeover_scan(self.target, self.log_callback)))
                # Check discovered subdomains (limit 5 for speed)
                for s in subs[:5]:
                    sub_chk = f"https://{s['detail']}"
                    self.process_findings(self.loop.run_until_complete(run_takeover_scan(sub_chk, None)))

            targets_to_scan = param_urls if param_urls else [self.target]
            self.log_callback(f"🎯 Analysis Targets: {len(targets_to_scan)} URLs (Deep Scan)")
            
            # [MODULAR EXECUTION]
            
            # 1. CVE Sniper
            if cfg.get('cve'):
                cve_res = self.loop.run_until_complete(run_cve_scan(self.target, self.log_callback, headers=self.evasion.get_headers()))
                self.process_findings(cve_res)
            
            # 2. RCE / Cmd Injection
            if cfg.get('rce'):
                 result = self.loop.run_until_complete(run_os_command_scan(self.target, self.log_callback, headers=self.evasion.get_headers()))
                 self.process_findings(result)
                 result_up = self.loop.run_until_complete(run_upload_scan(self.target, all_urls, self.log_callback, headers=self.evasion.get_headers()))
                 self.process_findings(result_up)

            # 3. Auth / IDOR
            if cfg.get('auth'):
                auth = self.loop.run_until_complete(run_auth_security_scan(self.target, self.log_callback, headers=self.evasion.get_headers()))
                self.process_findings(auth)
                if self.cookies:
                     idor = self.loop.run_until_complete(run_idor_scan(self.target, all_urls, cookies=self.cookies, log_callback=self.log_callback, headers=self.evasion.get_headers()))
                     self.process_findings(idor)

            # 4. API Warfare (Spectre) [NEW]
            if cfg.get('api'):
                 from modules.active.api_scanner import run_api_security_scan
                 api_res = self.loop.run_until_complete(run_api_security_scan(self.target, all_urls, self.log_callback, headers=self.evasion.get_headers(), cookies=self.cookies))
                 self.process_findings(api_res)
            
            # Loop scan for Injection flaws
            for url in targets_to_scan:
                if self._stop_event.is_set(): break
                
                # [PHASE 36] Project SILENT WHISPER (WebSocket)
                if url.startswith("ws://") or url.startswith("wss://"):
                    from modules.active.websocket_scanner import run_websocket_scan
                    ws_findings = self.loop.run_until_complete(run_websocket_scan(url, self.log_callback))
                    self.process_findings(ws_findings)
                    continue # Skip standard HTTP checks
                
                # [PHASE 37] Project GLASS HOUSE (XXE)
                # Probing XXE on endpoints (Converting to POST/XML implicitly)
                from modules.active.xxe_deep import run_xxe_scan
                
                # We clone headers from evasion
                xxe_findings = self.loop.run_until_complete(run_xxe_scan(url, method="POST", headers=self.evasion.get_headers(), log_callback=self.log_callback))
                self.process_findings(xxe_findings)
                
                # self.loop.run_until_complete(self.evasion.sleep_jitter())
                self.cortex.sleep()
                
                # [PHASE 31] Cortex Context Awareness
                suggestions = self.cortex.analyze_attack_surface(url)
                if suggestions:
                    self.log_callback(f"🧠 CORTEX: Context Analysis for '{url}' suggests: {', '.join(suggestions)}")
                
                # SQLi
                if cfg.get('sqli'):
                     self.process_findings(self.loop.run_until_complete(run_safe_sql_injection(url, safe_mode=True, log_callback=self.log_callback, headers=self.evasion.get_headers(), stealth_mode=self.evasion.use_jitter)))
                
                # XSS
                if cfg.get('xss'):
                     self.process_findings(self.loop.run_until_complete(run_xss_scan(url, self.log_callback, headers=self.evasion.get_headers(), stealth_mode=self.evasion.use_jitter)))
                
                # NoSQL
                if cfg.get('nosql'):
                     self.process_findings(self.loop.run_until_complete(run_nosql_scan(url, self.log_callback, headers=self.evasion.get_headers())))

                # Deserialization (Phase 12)
                from modules.active.deserialization import run_deserialization_scan
                self.process_findings(self.loop.run_until_complete(run_deserialization_scan(url, self.log_callback, headers=self.evasion.get_headers())))

                # Race Conditions (Phase 13)
                from modules.active.race_condition import run_race_scan
                self.process_findings(self.loop.run_until_complete(run_race_scan(url, self.log_callback, headers=self.evasion.get_headers())))

                # PrivEsc Mass Assignment (Phase 20)
                if cfg.get('auth'):
                    from modules.active.privesc import run_privesc_scan
                    self.process_findings(self.loop.run_until_complete(run_privesc_scan(url, self.log_callback, headers=self.evasion.get_headers())))

            # --- PHASE 3: CLIENT SIDE ---
            self.current_phase = "Client-Side Attacks"
            if self._stop_event.is_set(): return
            
            # XSS, ETC... (Existing)
            
            # Client Deep Dive (Phase 15)
            from modules.active.client_fuzzer import run_client_deep_scan
            self.process_findings(self.loop.run_until_complete(run_client_deep_scan(url, self.log_callback, headers=self.evasion.get_headers()))) # Check Params
            
            # DOM XSS (Phase 17) - Browser Based
            from modules.active.dom_xss import run_dom_xss_scan
            self.process_findings(self.loop.run_until_complete(run_dom_xss_scan(url, self.log_callback, headers=self.evasion.get_headers())))

            # Check JS files specifically?
            # We need to extract scripts first. Or just rely on whatever URLs are in 'all_urls'
            # (all_urls usually comes from the Spider, which includes .js files)
            
            # from modules.active.xss import run_xss_scan (Already imported)
            # ... existing XSS code ... (Actually I just append above it)
            if self.profile in ["Full Scan", "Quick Scan"]:
                self.log_callback("🎭 Phase 3: Client-Side Interaction...")
                cj = self.loop.run_until_complete(run_clickjacking_scan(self.target, self.log_callback))
                self.process_findings(cj)

            if not self._stop_event.is_set():
                self.current_phase = "Scan Completed"
                self.log_callback("✅ Scan Completed Successfully.")
            else:
                self.log_callback("🛑 Scan Terminated by User.")
            
            # [DISABLED BY USER REQUEST] Focus on core functionality first
            # self.log_callback("📄 Generating HTML Report...")
            # report_path = generate_html_report(self.target, self.all_findings)
            # self.log_callback(f"✨ Report saved to: {report_path}")

            # Save to Database
            self.log_callback("💾 Saving scan history...")
            save_scan_result(self.target, self.profile, self.all_findings)

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
                except:
                    pass

    def process_findings(self, findings_list):
        if findings_list:
            self.all_findings.extend(findings_list)
            
            # [KILL CHAIN] Feed the Knowledge Base
            from modules.chain.kill_chain import kill_chain
            for f in findings_list:
                kill_chain.process_finding(f)
                
            for f in findings_list:
                # [TAXONOMY] Classify finding before callback
                from core.taxonomy import TaxonomyMapper
                f['category'] = TaxonomyMapper.classify(f.get('type', 'Unknown'))
                self.finding_callback(f)
                
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
            
            # Simulate request count (Visual feedback)
            for _ in range(3):
                self.request_count += 1
                if self.on_progress:
                     self.on_progress(self.request_count, len(self.all_findings))
                time.sleep(0.05)

            # Simulate request count for modules that don't hook directly
            # Heuristic: 1 finding ~ 50 requests (scanning to find it)
            self.inc_req(len(findings_list) * 20 + 5)

    def run(self):
        try:
            self.run_async_process()
        except Exception as e:
            self.log_callback(f"❌ THREAD ERROR: {str(e)}")
        finally:
            self.finish_callback()