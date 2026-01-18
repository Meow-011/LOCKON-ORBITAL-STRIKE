import aiohttp
import asyncio
import re
import binascii
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# --- PAYLOADS & SIGNATURES ---

# Java Serialized Object (JSO) - Magic Bytes
# Hex: AC ED 00 05
JAVA_MAGIC_HEX = "aced0005"
JAVA_MAGIC_B64 = "rO0AB" # Base64 of aced0005

# PHP Serialization
# Pattern: O:4:"User":...
PHP_SERIAL_REGEX = r'[a-zA-Z]:\d+:"[^"]+":\d+:{'

# Python Pickle
# Pattern: (dp0 ... often ends with . or contains 'cos\nsystem' in exploit)
# We look for base64 encoded pickles too (difficult without context, but we check for common indicators)

async def check_deserialization(session, url):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params: return findings
    
    for param_name in params:
        orig_vals = params[param_name]
        for val in orig_vals:
            # 1. Passive Detection (Is it already serialized?)
            is_java = False
            is_php = False
            
            if JAVA_MAGIC_B64 in val or val.startswith(JAVA_MAGIC_HEX):
                is_java = True
                findings.append({
                    "type": "Insecure Deserialization (Java)",
                    "severity": "Medium", # High if we can exploit
                    "detail": f"Parameter '{param_name}' contains Java Serialized Object magic bytes.",
                    "evidence": f"Value: {val[:50]}...",
                    "remediation": "Do not accept serialized objects from untrusted sources."
                })
            
            if re.search(PHP_SERIAL_REGEX, val):
                is_php = True
                findings.append({
                    "type": "Insecure Deserialization (PHP)",
                    "severity": "Medium",
                    "detail": f"Parameter '{param_name}' appears to be a PHP Serialized string.",
                    "evidence": f"Value: {val[:50]}...",
                    "remediation": "Use JSON instead of serialize()."
                })

            # 2. Active Probing (If matched or just fuzzing)
            # Try to inject a harmless object to see if it causes 500 Error (Stack Trace)
            # Java: Send empty/invalid magic bytes to trigger EOFException or StreamCorruptedException
            fuzzed_params = params.copy()
            
            # [PROBE] Java Stream Corruption
            fuzzed_params[param_name] = ["rO0ABAAAAA=="] # Valid Header, Empty Content (Base64)
            target_java = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
            try:
                async with session.get(target_java, timeout=5, ssl=False) as resp:
                    text = await resp.text()
                    if "java.io" in text or "StreamCorruptedException" in text or "ObjectInputStream" in text:
                        findings.append({
                            "type": "Java Deserialization (Error Triggered)",
                            "severity": "High",
                            "detail": f"Triggered Java Deserialization error with crafted payload on '{param_name}'.",
                            "evidence": f"Error Snippet: {text[:200]}",
                        })
            except: pass
            
            # [PROBE] PHP Object Injection (Generic)
            # Try to inject an object that might cause issues or sleep (unlikely without known class)
            # Payload: O:8:"Exploit":0:{} - Tries to instantiate unknow class 'Exploit'
            fuzzed_params[param_name] = ['O:8:"Exploit":0:{}'] 
            target_php = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
            try:
                async with session.get(target_php, timeout=5, ssl=False) as resp:
                    text = await resp.text()
                    if "unserialize()" in text or "__wakeup" in text or "Object of class Exploit" in text:
                        findings.append({
                            "type": "PHP Object Injection",
                            "severity": "Critical",
                            "detail": f"Application attempted to deserialize injected PHP object on '{param_name}'.",
                            "evidence": f"Error Snippet: {text[:200]}",
                        })
            except: pass

    return findings

async def run_deserialization_scan(target_url, log_callback=None, headers=None):
    findings = []
    if "?" in target_url:
        if log_callback: log_callback(f"🧬 Checking for Insecure Deserialization (Java/PHP) on parameters...")
        async with aiohttp.ClientSession(headers=headers) as session:
            findings = await check_deserialization(session, target_url)
    return findings
