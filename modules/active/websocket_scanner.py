import aiohttp
import asyncio
import json

async def check_cswsh(url, log_callback=None):
    """
    Checks for Cross-Site WebSocket Hijacking by sending a malicious Origin header.
    """
    findings = []
    # Test CSWSH by sending a malicious Origin
    headers = {'Origin': 'https://evil.attacker.com'}
    
    try:
        async with aiohttp.ClientSession() as session:
            # Try to connect with malicious origin
            async with session.ws_connect(url, headers=headers, timeout=5) as ws:
                # If we get here (and didn't raise exception), connection was accepted!
                # Note: Some servers accept but immediately close. We check if it stays open briefly.
                
                # Try to send a ping or generic message to verify liveness
                await ws.send_str("PING")
                
                try:
                    # Expecting a response or at least no immediate disconnect
                    await ws.receive_timeout(2) 
                    
                    findings.append({
                        "type": "Cross-Site WebSocket Hijacking (CSWSH)",
                        "severity": "High",
                        "detail": "WebSocket server accepted connection with authorized Origin 'https://evil.attacker.com'.",
                        "evidence": "Connection established and messages exchanged successfully despite malicious Origin.",
                        "remediation": "Validate the 'Origin' header in the WebSocket handshake (server-side)."
                    })
                except asyncio.TimeoutError:
                     # Connection stayed open but no response, arguably still vulnerable if no 403 status during handshake
                     # But strictly, handshake success happens before ws_connect returns.
                     # So being in this block covers it.
                     findings.append({
                        "type": "Cross-Site WebSocket Hijacking (CSWSH)",
                        "severity": "High",
                        "detail": "WebSocket server accepted connection with malicious Origin.",
                        "evidence": "Handshake 101 Switching Protocols successful with Origin: https://evil.attacker.com",
                        "remediation": "Validate the 'Origin' header."
                    })
                
                await ws.close()
    except Exception as e:
        # Connection failed or rejected (403/401), which is secure behavior
        pass
        
    return findings

async def fuzz_frames(url, log_callback=None):
    """
    Fuzzes WebSocket frames with common payloads (XSS, SQLi, Injection).
    """
    findings = []
    payloads = [
        "<script>alert(1)</script>", 
        "' OR 1=1 --", 
        "{{7*7}}",
        "{\"msg\": \"<script>alert(1)</script>\"}", # JSON context
        "../../etc/passwd"
    ]
    
    try:
        async with aiohttp.ClientSession() as session:
             async with session.ws_connect(url, timeout=5) as ws:
                for p in payloads:
                    try:
                        await ws.send_str(p)
                        # Read response(s) with timeout
                        msg = await ws.receive_str(timeout=1.5)
                        
                        # Analyze msg for reflection or errors
                        if "<script>alert(1)</script>" in msg:
                             findings.append({
                                "type": "WebSocket XSS Detection",
                                "severity": "High",
                                "detail": f"Server reflected XSS payload back via WebSocket.",
                                "evidence": f"Sent: {p}\nReceived: {msg}",
                                "remediation": "Sanitize all input received via WebSockets."
                            })
                        elif "SQL syntax" in msg or "mysql_" in msg:
                             findings.append({
                                "type": "WebSocket SQL Injection",
                                "severity": "Critical",
                                "detail": f"Server returned SQL error via WebSocket.",
                                "evidence": f"Sent: {p}\nReceived: {msg}",
                                "remediation": "Use parameterized queries/statements."
                            })
                        elif "49" in msg and "{{7*7}}" in p: # SSTI 7*7=49
                             findings.append({
                                "type": "WebSocket SSTI",
                                "severity": "High",
                                "detail": f"Server executed Template Injection.",
                                "evidence": f"Sent: {p}\nReceived: {msg}",
                                "remediation": "Sanitize templates."
                            })
                    except: pass
    except: pass
    return findings

async def run_websocket_scan(url, log_callback=None):
    if log_callback: log_callback(f"🤫 SILENT WHISPER: Connecting to WebSocket {url}...")
    findings = []
    
    # 1. CSWSH
    cswsh = await check_cswsh(url, log_callback)
    if cswsh:
        findings.extend(cswsh)
        if log_callback: log_callback(f"   ⚠️ CSWSH Vulnerability Found!")
        
    # 2. Fuzzing
    # Only fuzz if we can connect normally
    fuzzed = await fuzz_frames(url, log_callback)
    if fuzzed:
        findings.extend(fuzzed)
        if log_callback: log_callback(f"   ⚠️ Frame Fuzzing found {len(fuzzed)} issues.")
        
    return findings
