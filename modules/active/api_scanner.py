import aiohttp
import asyncio
import json
import re
from urllib.parse import urlparse, urljoin
from modules.active.api_fuzzer import run_api_scan as fuzzer_scan
from modules.active.idor import run_idor_scan as idor_scan

SWAGGER_PATHS = [
    "/swagger.json",
    "/api/swagger.json",
    "/swagger/v1/swagger.json",
    "/v2/api-docs",
    "/api-docs",
    "/openapi.json",
    "/api/openapi.json"
]

async def check_swagger(session, base_url):
    """
    Tries to find Swagger/OpenAPI definitions to discover hidden endpoints.
    """
    findings = []
    discovered_endpoints = []
    
    for path in SWAGGER_PATHS:
        target = urljoin(base_url, path)
        try:
            async with session.get(target, timeout=5, ssl=False) as resp:
                if resp.status == 200:
                    try:
                        data = await resp.json()
                        if "swagger" in data or "openapi" in data:
                            findings.append({
                                "type": "Swagger/OpenAPI Definition Found",
                                "severity": "Info",
                                "detail": f"API Documentation exposed at {target}",
                                "evidence": f"URL: {target}\nVersion: {data.get('info', {}).get('version', 'Unknown')}",
                                "category": "API Security"
                            })
                            
                            # Parse endpoints
                            paths = data.get("paths", {})
                            for p in paths.keys():
                                full_ep = urljoin(base_url, p)
                                discovered_endpoints.append(full_ep)
                                
                            break # Found one, likely the main one
                    except:
                        pass
        except:
            pass
            
    return findings, discovered_endpoints

async def run_api_security_scan(target_url, all_urls, log_callback=None, headers=None, cookies=None):
    """
    Unified API Security Scanner:
    1. Swagger Discovery (Recon)
    2. API Fuzzing (BOLA, Mass Assignment, GraphQL) - via api_fuzzer.py
    3. IDOR Check - via idor.py
    """
    findings = []
    
    if log_callback: log_callback("⚡ Starting Protocol Spectre: API Security Analysis...")
    
    async with aiohttp.ClientSession(headers=headers) as session:
        # 1. Swagger Hunter
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        swagger_findings, new_eps = await check_swagger(session, base)
        if swagger_findings:
            if log_callback: log_callback(f"📜 Found Swagger Docs! Discovered {len(new_eps)} hidden endpoints.")
            findings.extend(swagger_findings)
            # Add new endpoints to the scan list
            all_urls.extend(new_eps)
    
        # 2. Existing Modules (Orchestration)
        # Scan discovered API endpoints
        api_targets = [u for u in all_urls if "api" in u or "/v" in u or ".json" in u]
        
        # Limit to avoid scanning thousands
        scan_limit = api_targets[:20] if len(api_targets) > 20 else api_targets
        
        tasks = []
        for url in scan_limit:
            tasks.append(fuzzer_scan(url, log_callback=None, headers=headers))
            
        if scan_limit:
            if log_callback: log_callback(f"🔌 Fuzzing {len(scan_limit)} API endpoints...")
            fuzz_results = await asyncio.gather(*tasks)
            for res in fuzz_results:
                findings.extend(res)
                
        # 3. IDOR (Specific Logic)
        idor_res = await idor_scan(target_url, all_urls, cookies=cookies, log_callback=log_callback, headers=headers)
        findings.extend(idor_res)

        # 4. GraphQL Scan (Phase 14)
        from modules.active.graphql import run_graphql_scan
        gql_res = await run_graphql_scan(target_url, log_callback=log_callback, headers=headers)
        findings.extend(gql_res)

        # 5. BOLA Heuristics (User A vs User B Simulation)
        # Since we don't have a second user token, we check for "Cross-User" access on common patterns
        # UUIDs found in URL? Try to swap with a random UUID.
        # If we get 200 OK -> High Chance of BOLA (or public resource)
        # If we get 403/401 -> Auth works.
        # If we get 404 -> Not found (Neutral).
        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        random_uuid = "123e4567-e89b-12d3-a456-426614174000" # Dummy UUID
        
        for url in scan_limit:
            if re.search(uuid_pattern, url):
                # Swap first UUID found
                swapped_url = re.sub(uuid_pattern, random_uuid, url, count=1)
                try:
                    async with session.get(swapped_url, headers=headers, timeout=5, ssl=False) as resp:
                        if resp.status == 200:
                             # Warning: Might be a public resource.
                             # Heuristic: Check if response is similar structure?
                             # For now, flag as "Potential"
                             findings.append({
                                "type": "Potential BOLA (Broken Object Level Authorization)",
                                "severity": "Medium",
                                "detail": f"Resource accessible with arbitrary UUID. Verify if this data should be public.",
                                "evidence": f"Original: {url}\nSwapped: {swapped_url}\nStatus: {resp.status} (OK)",
                                "remediation": "Enforce ownership checks on object access."
                             })
                except: pass
        
    return findings
