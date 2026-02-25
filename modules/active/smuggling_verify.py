import asyncio
import socket
from urllib.parse import urlparse

# Time-based Payloads
CL_TE_DELAY = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "{headers}"
    "Transfer-Encoding: chunked\r\n"
    "Content-Length: 4\r\n"
    "\r\n"
    "1\r\n"
    "A\r\n"
    "X" # Backend waits for next chunk size (0) -> Delay
)

TE_CL_DELAY = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "{headers}"
    "Transfer-Encoding: chunked\r\n"
    "Content-Length: 6\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "X" # Backend expects body size 6 -> Delay
)

async def check_timing_smuggling(target_url, payload_template, vuln_type, headers=None):
    parsed = urlparse(target_url)
    host = parsed.netloc.split(":")[0]
    port = 443 if parsed.scheme == "https" else 80
    if ":" in parsed.netloc: port = int(parsed.netloc.split(":")[1])
    
    # Form raw headers string
    header_str = ""
    if headers:
        for k, v in headers.items():
            if k.lower() not in ['host', 'transfer-encoding', 'content-length']:
                header_str += f"{k}: {v}\r\n"
    
    payload = payload_template.format(host=host, headers=header_str)
    
    try:
        reader, writer = await asyncio.open_connection(
            host, port, ssl=(port==443)
        )
        
        start_time = asyncio.get_event_loop().time()
        
        writer.write(payload.encode())
        await writer.drain()
        
        # Read response (or wait for timeout)
        try:
            await asyncio.wait_for(reader.read(1024), timeout=10)
        except asyncio.TimeoutError:
            # Timeout implies the server is waiting -> Vulnerable
            duration = asyncio.get_event_loop().time() - start_time
            if duration >= 5: # If delay is significant
                return {
                    "type": "HTTP Request Smuggling",
                    "severity": "Critical",
                    "detail": f"Server vulnerable to {vuln_type} desync (Time-based).",
                    "evidence": f"Request caused a delay of {duration:.2f}s",
                    "remediation": "Disable connection reuse or use HTTP/2 end-to-end."
                }
        
        writer.close()
        await writer.wait_closed()
        
    except Exception:
        pass
    
    return None

async def run_smuggling_verify(target_url, log_callback=None, headers=None):
    findings = []
    if log_callback: log_callback(f"🕵️ Verifying HTTP Request Smuggling (Time-Based)...")
    
    # Check CL.TE
    res1 = await check_timing_smuggling(target_url, CL_TE_DELAY, "CL.TE", headers=headers)
    if res1: findings.append(res1)
    
    # Check TE.CL
    res2 = await check_timing_smuggling(target_url, TE_CL_DELAY, "TE.CL", headers=headers)
    if res2: findings.append(res2)
    
    return findings