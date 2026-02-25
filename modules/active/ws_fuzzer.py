"""
Enhanced WebSocket Fuzzer
Advanced fuzzing with 30+ payloads, auth testing, DoS detection, and protocol violations.
"""
import asyncio
import aiohttp
import json
import time


# Payload categories
WS_PAYLOADS = {
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "'\"><img src=x onerror=alert(1)>",
        "javascript:alert(document.cookie)",
        "<body onload=alert(1)>",
    ],
    "sqli": [
        "' OR '1'='1' --",
        "' UNION SELECT NULL--",
        "1; DROP TABLE messages--",
        "admin'--",
        "' OR 1=1#",
        "1' AND '1'='1",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{constructor.constructor('return this')()}}",
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "/etc/passwd%00",
        "....//....//etc/passwd",
    ],
    "command_injection": [
        "; ls -la",
        "| cat /etc/passwd",
        "$(id)",
        "`whoami`",
        "|| ping -c 1 127.0.0.1",
    ],
    "nosql": [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$regex": ".*"}',
    ],
    "proto_pollution": [
        '{"__proto__": {"admin": true}}',
        '{"constructor": {"prototype": {"isAdmin": true}}}',
    ],
    "dos": [
        "A" * 65536,  # Oversized text frame
        "B" * 131072, # Very large frame
    ],
}

# Detection patterns for response analysis
DETECTION_PATTERNS = {
    "xss_reflected": ["<script>alert(1)</script>", "onerror=alert", "onload=alert"],
    "sql_error": ["SQL syntax", "mysql_", "ORA-", "sqlite3.", "pq:", "SQLSTATE"],
    "ssti_eval": ["49"],  # 7*7 = 49
    "path_content": ["root:", "[extensions]", "win.ini"],
    "cmd_output": ["uid=", "www-data", "root", "bin/bash"],
    "error_leak": ["traceback", "stack trace", "exception", "error at line"],
}


async def run_ws_fuzzer(url, log_callback=None, headers=None):
    """
    Full WebSocket fuzzer. Discovers WS endpoints and runs comprehensive fuzzing.
    
    Args:
        url: WebSocket URL (ws:// or wss://)
        log_callback: Logging function
        headers: Additional headers dict
    
    Returns:
        List of finding dicts
    """
    log = log_callback or (lambda m: None)
    findings = []

    # Normalize URL
    if url.startswith("http://"):
        ws_url = "ws://" + url[7:]
    elif url.startswith("https://"):
        ws_url = "wss://" + url[8:]
    elif not url.startswith("ws"):
        ws_url = "ws://" + url
    else:
        ws_url = url

    log(f"🔌 WS Fuzzer: Connecting to {ws_url}")

    # 1. Connection test
    try:
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(ws_url, headers=headers, timeout=5) as ws:
                log(f"   ✅ WebSocket connection established")
                await ws.close()
    except Exception as e:
        log(f"   ❌ Cannot connect: {e}")
        return findings

    # 2. CSWSH (Cross-Site WebSocket Hijacking)
    cswsh = await _check_cswsh(ws_url, log)
    findings.extend(cswsh)

    # 3. Auth bypass test
    auth_findings = await _check_auth_bypass(ws_url, log)
    findings.extend(auth_findings)

    # 4. Payload fuzzing
    for category, payloads in WS_PAYLOADS.items():
        if category == "dos":
            continue  # DoS tested separately
        
        log(f"   🎯 Fuzzing: {category} ({len(payloads)} payloads)")
        for payload in payloads:
            result = await _fuzz_single(ws_url, payload, category, headers, log)
            if result:
                findings.append(result)

    # 5. DoS resilience test (optional, lightweight)
    dos_findings = await _check_dos_resilience(ws_url, log)
    findings.extend(dos_findings)

    # 6. Protocol violation test
    proto_findings = await _check_protocol_violations(ws_url, log)
    findings.extend(proto_findings)

    if findings:
        log(f"🔌 WS Fuzzer: {len(findings)} issues found")
    else:
        log(f"🔌 WS Fuzzer: No issues found")

    return findings


async def _check_cswsh(ws_url, log):
    """Check Cross-Site WebSocket Hijacking."""
    findings = []
    evil_origins = [
        "https://evil.attacker.com",
        "https://attacker.io",
        "null",
    ]

    for origin in evil_origins:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(
                    ws_url, headers={"Origin": origin}, timeout=5
                ) as ws:
                    # Connection accepted with evil origin
                    await ws.send_str("ping")
                    try:
                        await asyncio.wait_for(ws.receive(), timeout=2)
                    except asyncio.TimeoutError:
                        pass
                    
                    findings.append({
                        "type": "Cross-Site WebSocket Hijacking (CSWSH)",
                        "severity": "High",
                        "detail": f"WebSocket accepted connection from malicious Origin: {origin}",
                        "url": ws_url,
                        "evidence": f"Origin header '{origin}' was accepted. Handshake completed successfully.",
                        "remediation": "Validate the Origin header during WebSocket handshake. Only accept connections from trusted origins.",
                        "cwe": "CWE-346",
                    })
                    log(f"   ⚠️ CSWSH: Accepted Origin '{origin}'")
                    await ws.close()
                    break  # One confirmed is enough
        except Exception:
            pass  # Connection rejected = secure

    return findings


async def _check_auth_bypass(ws_url, log):
    """Test WebSocket without authentication."""
    findings = []
    try:
        async with aiohttp.ClientSession() as session:
            # Connect without any auth headers
            async with session.ws_connect(ws_url, timeout=5) as ws:
                # Try sending a privileged-looking message
                test_msgs = [
                    '{"action": "getUsers"}',
                    '{"type": "admin", "cmd": "list"}',
                    '{"query": "SELECT * FROM users"}',
                ]
                for msg in test_msgs:
                    await ws.send_str(msg)
                    try:
                        resp = await asyncio.wait_for(ws.receive(), timeout=2)
                        if resp.type == aiohttp.WSMsgType.TEXT:
                            data = resp.data.lower()
                            # Check for data leakage indicators
                            if any(kw in data for kw in ["user", "email", "admin", "password", "token", "id"]):
                                findings.append({
                                    "type": "WebSocket Authentication Bypass",
                                    "severity": "High",
                                    "detail": "WebSocket endpoint returned sensitive data without authentication.",
                                    "url": ws_url,
                                    "evidence": f"Sent: {msg}\nReceived: {resp.data[:500]}",
                                    "remediation": "Implement authentication checks for WebSocket connections.",
                                    "cwe": "CWE-306",
                                })
                                log(f"   ⚠️ Auth bypass: Returned data for '{msg[:40]}'")
                                break
                    except asyncio.TimeoutError:
                        pass
                await ws.close()
    except Exception:
        pass
    return findings


async def _fuzz_single(ws_url, payload, category, headers, log):
    """Send a single fuzz payload and analyze response."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(ws_url, headers=headers, timeout=5) as ws:
                await ws.send_str(payload)
                
                try:
                    resp = await asyncio.wait_for(ws.receive(), timeout=2)
                    if resp.type != aiohttp.WSMsgType.TEXT:
                        return None
                    
                    data = resp.data
                    
                    # Check for vulnerability indicators
                    finding = _analyze_response(data, payload, category, ws_url)
                    if finding:
                        log(f"   🎯 {category.upper()}: Response indicates vulnerability")
                        return finding
                    
                except asyncio.TimeoutError:
                    pass
                
                await ws.close()
    except Exception:
        pass
    return None


def _analyze_response(response, payload, category, url):
    """Analyze a WebSocket response for vulnerability indicators."""
    resp_lower = response.lower()

    # XSS reflection
    if category == "xss":
        for pattern in DETECTION_PATTERNS["xss_reflected"]:
            if pattern.lower() in resp_lower:
                return {
                    "type": "WebSocket XSS (Reflected)",
                    "severity": "High",
                    "detail": "XSS payload reflected back through WebSocket without sanitization.",
                    "url": url,
                    "evidence": f"Sent: {payload}\nReceived: {response[:500]}",
                    "remediation": "Sanitize all input received via WebSocket before echoing or rendering.",
                    "cwe": "CWE-79",
                }

    # SQL Injection
    if category == "sqli":
        for pattern in DETECTION_PATTERNS["sql_error"]:
            if pattern.lower() in resp_lower:
                return {
                    "type": "WebSocket SQL Injection",
                    "severity": "Critical",
                    "detail": "SQL error returned via WebSocket, indicating injection vulnerability.",
                    "url": url,
                    "evidence": f"Sent: {payload}\nReceived: {response[:500]}",
                    "remediation": "Use parameterized queries for all database operations triggered via WebSocket.",
                    "cwe": "CWE-89",
                }

    # SSTI
    if category == "ssti" and "{{7*7}}" in payload:
        for pattern in DETECTION_PATTERNS["ssti_eval"]:
            if pattern in response and "7*7" not in response:
                return {
                    "type": "WebSocket SSTI",
                    "severity": "High",
                    "detail": "Server evaluated template expression via WebSocket.",
                    "url": url,
                    "evidence": f"Sent: {payload}\nReceived: {response[:500]}",
                    "remediation": "Do not pass user input to template engines without sandboxing.",
                    "cwe": "CWE-1336",
                }

    # Path Traversal
    if category == "path_traversal":
        for pattern in DETECTION_PATTERNS["path_content"]:
            if pattern.lower() in resp_lower:
                return {
                    "type": "WebSocket Path Traversal",
                    "severity": "High",
                    "detail": "File content returned via WebSocket path traversal.",
                    "url": url,
                    "evidence": f"Sent: {payload}\nReceived: {response[:500]}",
                    "remediation": "Validate and sanitize file paths. Use a whitelist of allowed files.",
                    "cwe": "CWE-22",
                }

    # Command Injection
    if category == "command_injection":
        for pattern in DETECTION_PATTERNS["cmd_output"]:
            if pattern.lower() in resp_lower:
                return {
                    "type": "WebSocket Command Injection",
                    "severity": "Critical",
                    "detail": "OS command output returned via WebSocket.",
                    "url": url,
                    "evidence": f"Sent: {payload}\nReceived: {response[:500]}",
                    "remediation": "Never pass user input to system commands. Use safe APIs.",
                    "cwe": "CWE-78",
                }

    # Error info leakage
    for pattern in DETECTION_PATTERNS["error_leak"]:
        if pattern.lower() in resp_lower:
            return {
                "type": "WebSocket Error Information Leak",
                "severity": "Low",
                "detail": f"Server leaked error information via WebSocket when processing payload.",
                "url": url,
                "evidence": f"Sent: {payload}\nReceived: {response[:500]}",
                "remediation": "Implement generic error handling for WebSocket messages.",
                "cwe": "CWE-209",
            }

    return None


async def _check_dos_resilience(ws_url, log):
    """Lightweight DoS resilience check — send oversized frame."""
    findings = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(ws_url, timeout=5) as ws:
                # Send a large payload
                large_payload = "X" * 65536
                start = time.time()
                await ws.send_str(large_payload)
                
                try:
                    resp = await asyncio.wait_for(ws.receive(), timeout=3)
                    elapsed = time.time() - start
                    
                    if elapsed > 2:
                        findings.append({
                            "type": "WebSocket DoS — Slow Processing",
                            "severity": "Medium",
                            "detail": f"Server took {elapsed:.1f}s to process 64KB frame. May be vulnerable to DoS.",
                            "url": ws_url,
                            "evidence": f"Sent 65536 bytes, response took {elapsed:.1f}s",
                            "remediation": "Implement message size limits and rate limiting for WebSocket connections.",
                            "cwe": "CWE-400",
                        })
                        log(f"   ⚠️ DoS: Slow response ({elapsed:.1f}s) to oversized frame")
                except asyncio.TimeoutError:
                    pass
                
                await ws.close()
    except Exception:
        pass
    return findings


async def _check_protocol_violations(ws_url, log):
    """Test server handling of malformed messages."""
    findings = []
    malformed = [
        b"\xff\xfe",  # Invalid UTF-8
        b"\x00" * 100,  # Null bytes
    ]

    try:
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(ws_url, timeout=5) as ws:
                for payload in malformed:
                    try:
                        await ws.send_bytes(payload)
                        resp = await asyncio.wait_for(ws.receive(), timeout=2)
                        
                        if resp.type == aiohttp.WSMsgType.TEXT:
                            data = resp.data.lower()
                            if any(kw in data for kw in ["error", "exception", "traceback", "stack"]):
                                findings.append({
                                    "type": "WebSocket Protocol Violation Leak",
                                    "severity": "Low",
                                    "detail": "Server leaked error info when handling malformed WebSocket frame.",
                                    "url": ws_url,
                                    "evidence": f"Sent malformed frame, received: {resp.data[:300]}",
                                    "remediation": "Handle malformed WebSocket frames gracefully without exposing internals.",
                                    "cwe": "CWE-209",
                                })
                                log(f"   ⚠️ Protocol violation: Error leak on malformed frame")
                                break
                    except Exception:
                        pass
                
                await ws.close()
    except Exception:
        pass
    return findings
