import asyncio
import socket

# Top 100 Common Ports (Fast Scan)
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 465, 587, 
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 
    9000, 9200, 27017
]

async def check_port(target, port, timeout=1):
    try:
        conn = asyncio.open_connection(target, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port, True
    except:
        return port, False

async def run_native_port_scan(target_url, log_callback=None):
    findings = []
    hostname = target_url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    
    if log_callback: log_callback(f"⚡ Starting Native Async Port Scan on {hostname}...")
    
    tasks = []
    for port in COMMON_PORTS:
        tasks.append(check_port(hostname, port))
    
    results = await asyncio.gather(*tasks)
    
    open_ports = []
    for port, is_open in results:
        if is_open:
            open_ports.append(str(port))
            
    if open_ports:
        findings.append({
            "type": "Open Ports (Native Scan)",
            "severity": "Info",
            "detail": f"Found {len(open_ports)} open ports.",
            "evidence": f"Open Ports: {', '.join(open_ports)}",
            "remediation": "Close unnecessary ports via Firewall."
        })
        if log_callback: log_callback(f"   Open ports: {', '.join(open_ports)}")
        
    return findings