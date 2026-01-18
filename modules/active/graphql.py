import aiohttp
import asyncio
import json

GRAPHQL_ENDPOINTS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/graph", "/query"
]

async def check_introspection(session, url):
    """ Checks if Introspection is enabled. """
    payload = {
        "query": "query { __schema { types { name } } }"
    }
    try:
        async with session.post(url, json=payload, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json()
                if "data" in data and "__schema" in data["data"]:
                    return True
    except: pass
    return False

async def check_batching(session, url):
    """ Checks if Batching is enabled (Array of queries). """
    # Send array of 3 harmless queries
    payload = [
        {"query": "query { __typename }"},
        {"query": "query { __typename }"},
        {"query": "query { __typename }"}
    ]
    try:
        async with session.post(url, json=payload, timeout=5, ssl=False) as resp:
            if resp.status == 200:
                text = await resp.text()
                # If we get a JSON array response back with 3 results
                if text.strip().startswith("[") and text.count("__typename") >= 3:
                    return True
    except: pass
    return False

async def run_graphql_scan(target_url, log_callback=None, headers=None):
    findings = []
    
    # 1. Discovery - Check common endpoints
    found_graphql = []
    async with aiohttp.ClientSession(headers=headers) as session:
        for path in GRAPHQL_ENDPOINTS:
            # Construct full URL. Simple join might be risky if target_url has path.
            # Assume target_url is base.
            if target_url.endswith("/"): base = target_url[:-1]
            else: base = target_url
            
            gql_url = f"{base}{path}"
            
            try:
                # Basic check: GET or POST
                async with session.get(gql_url, timeout=3, ssl=False) as resp:
                    if resp.status != 404:
                         # Likely exists, try to query
                         if await check_introspection(session, gql_url):
                             found_graphql.append(gql_url)
                             findings.append({
                                 "type": "GraphQL Introspection Enabled",
                                 "severity": "Medium",
                                 "detail": f"GraphQL Introspection is enabled at {gql_url}. Attackers can map the entire schema.",
                                 "evidence": "Query: { __schema { types { name } } }",
                                 "remediation": "Disable Introspection in production."
                             })
            except: pass
            
        # 2. Attacks on Found Endpoints
        for gql_url in found_graphql:
            # Batching
            if await check_batching(session, gql_url):
                findings.append({
                    "type": "GraphQL Batching Attack Supported",
                    "severity": "Low",
                    "detail": f"Endpoint {gql_url} supports query batching. Potential for DoS or Rate Limit Bypass.",
                    "evidence": "Sent array of 3 queries, received array of 3 responses.",
                    "remediation": "Disable query batching or limit complexity."
                })
                
    return findings
