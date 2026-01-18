import asyncio

class ChainReactor:
    """
    Project DOMINO: Chain Reaction Engine.
    Triggers follow-up modules based on findings context (e.g. Found CMS -> Run CMS Scan).
    """
    def __init__(self, scanner):
        self.scanner = scanner
        self.triggered_chains = set() # To prevent infinite loops or duplicate triggers
        
    def react(self, findings):
        """
        Analyzes findings and triggers new scan tasks.
        Returns a list of task descriptions (strings) for logging.
        """
        triggered_actions = []
        
        # --- Evasion Integration (Project PHANTOM CHAIN) ---
        evasion_headers = {}
        proxy = None
        if hasattr(self.scanner, 'evasion_manager') and self.scanner.evasion_manager:
            evasion_headers = self.scanner.evasion_manager.get_headers()
            proxy = self.scanner.evasion_manager.get_proxy()
        # ---------------------------------------------------
        
        for f in findings:
            # Unique ID for the finding context to avoid re-triggering
            # e.g. "WORDPRESS_DETECTED_http://target.com"
            f_type = f.get('type', '').upper()
            f_detail = f.get('detail', '')
            f_url = self.scanner.target # Assuming simplistic target association
            
            chain_id = f"{f_type}_{f_url}"
            if chain_id in self.triggered_chains:
                continue

            # --- RULE 1: CMS Detection ---
            if "WORDPRESS" in f_type or "WORDPRESS" in f_detail.upper():
                self.triggered_chains.add(chain_id)
                action = "Run WP User Enum"
                triggered_actions.append(action)
                # In a real engine, we would schedule a specific task here.
                # self.scanner.schedule_task(wp_enum_task, f_url)
                # For this prototype, we mock the scheduling or call it if available.
                # Let's assume we just log it for Phase 39, or implement basic if-then.
                
                # Example: If we had a module modules.active.cms_scanner.scan_wordpress
                # self.scanner.loop.create_task(scan_wordpress(f_url))
                pass

            # --- RULE 2: SQL Injection (Auto-Dump) ---
            if "SQL INJECTION" in f_type:
                self.triggered_chains.add(chain_id)
                
                # Extract param from detail if possible
                import re
                param_match = re.search(r"via '([^']+)'", f_detail)
                target_param = param_match.group(1) if param_match else None
                
                # Schedule Async Task
                from modules.exploit.sqli_dumper import exploit_sqli_dump
                
                async def run_sqli_dump(u, p):
                    # We need to callback with findings
                    dumps = await exploit_sqli_dump(u, p, self.scanner.log_callback, headers=evasion_headers, proxy=proxy)
                    if dumps:
                        self.scanner.process_findings(dumps)
                        
                self.scanner.loop.create_task(run_sqli_dump(f_url, target_param))
                
                action = f"Attempt Schema Dump (Heavy Query) on param '{target_param}'"
                triggered_actions.append(action)
                
            # --- RULE 3: LFI (RCE Upgrade) ---
            if "LOCAL FILE INCLUSION" in f_type:
                self.triggered_chains.add(chain_id)
                
                import re
                param_match = re.search(r"via '([^']+)'", f_detail)
                target_param = param_match.group(1) if param_match else None
                
                from modules.exploit.lfi_rce import exploit_lfi_to_rce
                
                async def run_lfi_rce(u, p):
                     rces = await exploit_lfi_to_rce(u, p, self.scanner.log_callback, headers=evasion_headers, proxy=proxy)
                     if rces:
                         self.scanner.process_findings(rces)

                self.scanner.loop.create_task(run_lfi_rce(f_url, target_param))
                
                action = "Attempt LFI to RCE (Log Poisoning)"
                triggered_actions.append(action)

            # --- RULE 4: Reflected XSS (Cookie Stealer) ---
            if "REFLECTED XSS" in f_type:
                self.triggered_chains.add(chain_id)
                
                import re
                param_match = re.search(r"via '([^']+)'", f_detail)
                target_param = param_match.group(1) if param_match else None
                
                from modules.exploit.xss_stealer import exploit_xss_stealer
                
                async def run_xss_steal(u, p):
                     stealers = await exploit_xss_stealer(u, p, self.scanner.log_callback, headers=evasion_headers, proxy=proxy)
                     if stealers: self.scanner.process_findings(stealers)
                     
                self.scanner.loop.create_task(run_xss_steal(f_url, target_param))
                triggered_actions.append("Attempt XSS Cookie Stealer (OAST)")

            # --- RULE 5: IDOR (Mass Harvesting) ---
            if "IDOR" in f_type:
                self.triggered_chains.add(chain_id)
                
                import re
                param_match = re.search(r"via '([^']+)'", f_detail)
                target_param = param_match.group(1) if param_match else None
                
                from modules.exploit.idor_harvester import exploit_idor_harvester
                
                async def run_idor_harvest(u, p):
                     loot = await exploit_idor_harvester(u, p, self.scanner.log_callback, headers=evasion_headers, proxy=proxy)
                     if loot: self.scanner.process_findings(loot)

                self.scanner.loop.create_task(run_idor_harvest(f_url, target_param))
                triggered_actions.append("Attempt IDOR Mass Harvesting")

            # --- RULE 6: Git Exposure (Looter) ---
            if "GIT" in f_type or ".GIT" in f_detail.upper():
                self.triggered_chains.add(chain_id)
                
                from modules.exploit.git_looter import exploit_git_looter
                
                async def run_git_loot(u, p):
                     loot = await exploit_git_looter(u, p, self.scanner.log_callback, headers=evasion_headers, proxy=proxy)
                     if loot: self.scanner.process_findings(loot)

                self.scanner.loop.create_task(run_git_loot(f_url, None))
                triggered_actions.append("Attempt Git Secret Looter")

            # --- RULE 7: SSRF (Internal Pivot) ---
            if "SSRF" in f_type:
                self.triggered_chains.add(chain_id)
                
                import re
                param_match = re.search(r"via '([^']+)'", f_detail)
                target_param = param_match.group(1) if param_match else None
                
                from modules.exploit.ssrf_pivot import exploit_ssrf_pivot
                
                async def run_ssrf(u, p):
                     res = await exploit_ssrf_pivot(u, p, self.scanner.log_callback, headers=evasion_headers, proxy=proxy)
                     if res: self.scanner.process_findings(res)
                     
                self.scanner.loop.create_task(run_ssrf(f_url, target_param))
                triggered_actions.append("Attempt SSRF Internal Pivoting")

            # --- RULE 8: Unrestricted Upload (Shell Planter) ---
            if "UPLOAD" in f_type or "FILE UPLOAD" in f_type:
                self.triggered_chains.add(chain_id)
                
                from modules.exploit.shell_planter import exploit_web_shell
                
                async def run_shell(u, p):
                     res = await exploit_web_shell(u, p, self.scanner.log_callback, headers=evasion_headers, proxy=proxy)
                     if res: self.scanner.process_findings(res)

                self.scanner.loop.create_task(run_shell(f_url, None))
                triggered_actions.append("Attempt Persistent Web Shell Upload")

            # --- RULE 9: Weak JWT (Admin Forger) ---
            if "JWT" in f_type or "TOKEN" in f_type and "WEAK" in f_type:
                self.triggered_chains.add(chain_id)
                
                # We need the token string. It might be in detail or evidence?
                # Assume it's in detail for now or we skip.
                # Actually, scanner usually puts token in 'detail' like "Weak JWT found: eyJ..."
                import re
                token_match = re.search(r"(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)", f_detail)
                token = token_match.group(1) if token_match else None
                
                if token:
                    from modules.exploit.jwt_forger import exploit_jwt_forge
                    
                    async def run_jwt(u, p):
                         res = await exploit_jwt_forge(u, p, self.scanner.log_callback, headers=evasion_headers, proxy=proxy)
                         if res: self.scanner.process_findings(res)

                    self.scanner.loop.create_task(run_jwt(f_url, token))
                    triggered_actions.append("Attempt JWT Admin Forgery")

            # --- RULE 10: Password Reset Poisoning (Viper) ---
            if "RESET" in f_detail.upper() or "FORGOT" in f_detail.upper():
                self.triggered_chains.add(chain_id)
                
                from modules.exploit.password_reset_poison import exploit_reset_poison
                
                async def run_reset_poison(u, p):
                     res = await exploit_reset_poison(u, p, self.scanner.log_callback, headers=evasion_headers, proxy=proxy)
                     if res: self.scanner.process_findings(res)

                self.scanner.loop.create_task(run_reset_poison(f_url, None))
                triggered_actions.append("Attempt Password Reset Poisoning")

            # --- RULE 11: Mass Assignment PrivEsc (Viper) ---
            if "MASS" in f_type.upper() or "ASSIGNMENT" in f_type.upper():
                self.triggered_chains.add(chain_id)
                
                from modules.exploit.mass_assignment_privesc import exploit_mass_assignment
                
                async def run_privesc(u, p):
                     res = await exploit_mass_assignment(u, p, self.scanner.log_callback, headers=evasion_headers, proxy=proxy)
                     if res: self.scanner.process_findings(res)

                self.scanner.loop.create_task(run_privesc(f_url, None))
                triggered_actions.append("Attempt Mass Assignment PrivEsc")

            # --- RULE 12: Smart Brute Force (Cerberus) ---
            if "USER" in f_type.upper() or "ENUM" in f_type.upper():
                self.triggered_chains.add(chain_id)
                
                # Try to extract username list
                # Simple heuristic: if finding detail lists users "Found: admin, test"
                usernames = []
                if "admin" in f_detail: usernames.append("admin")
                if "test" in f_detail: usernames.append("test")
                if "root" in f_detail: usernames.append("root")
                
                from modules.exploit.smart_brute import exploit_smart_brute
                
                async def run_brute(u, users):
                     res = await exploit_smart_brute(u, users, self.scanner.log_callback, headers=evasion_headers, proxy=proxy)
                     if res: self.scanner.process_findings(res)

                self.scanner.loop.create_task(run_brute(f_url, usernames))
                triggered_actions.append("Attempt Smart Brute Force")

            # --- RULE 13: Default Creds Spray (Cerberus) ---
            tech_triggers = ["TOMCAT", "JENKINS", "WORDPRESS", "BASIC AUTH"]
            detected_tech = next((t for t in tech_triggers if t in f_type.upper() or t in f_detail.upper()), None)
            
            if detected_tech:
                self.triggered_chains.add(chain_id)
                
                from modules.exploit.default_creds_spray import exploit_default_creds
                
                async def run_spray(u, tech):
                     res = await exploit_default_creds(u, tech, self.scanner.log_callback, headers=evasion_headers, proxy=proxy)
                     if res: self.scanner.process_findings(res)

                self.scanner.loop.create_task(run_spray(f_url, detected_tech))
                triggered_actions.append(f"Attempt Default Creds Spray ({detected_tech})")

            # --- RULE 14: GraphQL Introspection (Kraken) ---
            if "GRAPHQL" in f_type.upper():
                self.triggered_chains.add(chain_id)
                
                from modules.exploit.graphql_dumper import exploit_graphql_dump
                
                async def run_graphql(u, p):
                     res = await exploit_graphql_dump(u, p, self.scanner.log_callback, headers=evasion_headers, proxy=proxy)
                     if res: self.scanner.process_findings(res)

                self.scanner.loop.create_task(run_graphql(f_url, None))
                triggered_actions.append("Attempt GraphQL Schema Dump")

            # --- RULE 15: Firebase Takeover (Kraken) ---
            if "FIREBASE" in f_type.upper() or "FIREBASE" in f_detail.upper():
                self.triggered_chains.add(chain_id)
                
                # Check if URL itself is firebase, or if we need to parse config
                target_fb_url = f_url if "firebaseio.com" in f_url else None
                # If we don't have the FB url in f_url, maybe it's in detail?
                # For now simplify: trigger if URL is firebase
                
                if target_fb_url:
                    from modules.exploit.firebase_takeover import exploit_firebase
                    
                    async def run_firebase(u, c):
                         res = await exploit_firebase(u, c, self.scanner.log_callback, headers=evasion_headers, proxy=proxy)
                         if res: self.scanner.process_findings(res)

                    self.scanner.loop.create_task(run_firebase(target_fb_url, None))
                    triggered_actions.append("Attempt Firebase Takeover")

            # --- RULE 16: Cloud Key Validation (Kraken) ---
            if "AWS" in f_type.upper() or "GCP" in f_type.upper() or "ACCESS KEY" in f_type.upper():
                self.triggered_chains.add(chain_id)
                
                provider = "AWS" if "AWS" in f_type.upper() else "GCP"
                # Extract key from detail/evidence?
                # Assume Evidence contains the key
                key = None # Extraction logic needed
                # Placeholder extraction based on regex?
                import re
                if provider == "AWS":
                    m = re.search(r"(AKIA[A-Z0-9]{16})", f_detail)
                    key = m.group(1) if m else None
                elif provider == "GCP":
                    m = re.search(r"(AIza[a-zA-Z0-9_\\-]+)", f_detail)
                    key = m.group(1) if m else None
                    
                if key:
                    from modules.exploit.cloud_key_validator import exploit_cloud_keys
                    
                    async def run_cloud(u, k):
                         res = await exploit_cloud_keys(u, k, provider, self.scanner.log_callback, headers=evasion_headers, proxy=proxy)
                         if res: self.scanner.process_findings(res)
                    
                    self.scanner.loop.create_task(run_cloud(f_url, key))
                    triggered_actions.append(f"Attempt Cloud Key Validation ({provider})")

            # --- RULE 17: Log4Shell Killer (Hydra) ---
            if "JAVA" in f_type.upper() or "TOMCAT" in f_type.upper() or "SPRING" in f_type.upper():
                self.triggered_chains.add(chain_id)
                
                from modules.exploit.log4shell_killer import exploit_log4shell
                
                async def run_log4j(u, p):
                     res = await exploit_log4shell(u, p, self.scanner.log_callback, headers=evasion_headers, proxy=proxy)
                     if res: self.scanner.process_findings(res)

                self.scanner.loop.create_task(run_log4j(f_url, None))
                triggered_actions.append("Attempt Log4Shell Injection")

            # --- RULE 18: Shellshock Trigger (Hydra) ---
            if "CGI" in f_type.upper() or "BASH" in f_type.upper() or ".sh" in f_url or ".pl" in f_url:
                self.triggered_chains.add(chain_id)
                
                from modules.exploit.shellshock_trigger import exploit_shellshock
                
                async def run_shellshock(u, p):
                     res = await exploit_shellshock(u, p, self.scanner.log_callback, headers=evasion_headers, proxy=proxy)
                     if res: self.scanner.process_findings(res)

                self.scanner.loop.create_task(run_shellshock(f_url, None))
                triggered_actions.append("Attempt Shellshock Injection")

            # --- RULE 19: CVE Hunter (Hydra) ---
            if "VERSION" in f_type.upper():
                self.triggered_chains.add(chain_id)
                
                # Extract version from detail "Found Apache 2.4.49"
                version_str = f_detail
                
                from modules.exploit.cve_hunter import exploit_cve
                
                async def run_cve(u, v):
                     res = await exploit_cve(u, v, self.scanner.log_callback, headers=evasion_headers, proxy=proxy)
                     if res: self.scanner.process_findings(res)
                     
                self.scanner.loop.create_task(run_cve(f_url, version_str))
                triggered_actions.append("Attempt Known CVE Exploit")

            # --- RULE 20: Config Hunter (Deep Impact) ---
            if "LFI" in f_type or "LEAK" in f_type or "EXPOSURE" in f_type:
                self.triggered_chains.add(chain_id + "_CONFIG")
                
                # Determine param if LFI
                import re
                param_match = re.search(r"via '([^']+)'", f_detail)
                target_param = param_match.group(1) if param_match else None
                
                from modules.exploit.config_hunter import exploit_config_hunter
                
                async def run_config(u, p):
                     res = await exploit_config_hunter(u, p, self.scanner.log_callback, headers=evasion_headers, proxy=proxy)
                     if res: self.scanner.process_findings(res)
                     
                self.scanner.loop.create_task(run_config(f_url, target_param))
                triggered_actions.append("Attempt Config & Secret Hunting")

        return triggered_actions
