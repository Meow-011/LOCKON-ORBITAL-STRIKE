import aiohttp
import asyncio
import time

# Heuristics for Race Condition Targets
# These keywords suggest a limited resource or single-use action
RACE_TARGET_KEYWORDS = [
    "coupon", "voucher", "gift", "transfer", "redeem", "vote", "like", 
    "limit", "claim", "promo", "signup", "register"
]

async def send_race_request(session, url, data=None, method="POST"):
    """ Sends a single request for the race condition test. """
    try:
        # Use a short timeout to try and keep requests synchronized
        if method == "POST":
            async with session.post(url, data=data, timeout=5, ssl=False) as resp:
                return resp.status, len(await resp.read())
        else:
            async with session.get(url, timeout=5, ssl=False) as resp:
                return resp.status, len(await resp.read())
    except:
        return 0, 0

async def check_race_condition(session, url, method="POST"):
    findings = []
    
    # 1. Target Identify
    # Only test if URL suggests a race-prone action
    is_target = False
    for kw in RACE_TARGET_KEYWORDS:
        if kw in url.lower():
            is_target = True
            break
            
    if not is_target: return findings
    
    # 2. Race Attack (Flood)
    # Send 15 requests simultaneously
    BATCH_SIZE = 15
    tasks = []
    
    # Need dummy data if POST and no data provided? 
    # For now, we assume the URL might have query params or we just send empty body if unspecified.
    # Ideally, this module hooks into a Crawler that provides the body. 
    # Since we are "Active Scanning" URL lists, we might not have body. 
    # We will assume Query Param based operations or simple POSTs.
    
    # Synchronization Barrier?
    # In asyncio, gathering tasks starts them "almost" at once.
    # True synchronization needs low-level socket manipulation (Turbo Intruder style).
    # But for a scanner, `gather` is "good enough" for loose race conditions.
    
    for _ in range(BATCH_SIZE):
        tasks.append(send_race_request(session, url, method=method))
        
    results = await asyncio.gather(*tasks)
    
    # 3. Analyze Results
    # If we get multiple "Success" (200/201) responses that are identical?
    # Or if the application handles it correctly, maybe 1 Success and 14 Errors.
    
    success_count = 0
    status_codes = []
    for status, length in results:
        status_codes.append(status)
        if 200 <= status < 300:
            success_count += 1
            
    # Risk Heuristic:
    # If > 50% successful on a sensitive action, it MIGHT be a race (or just idempotent).
    # This is tricky. Idempotent actions (like "Update Profile") SHOULD succeed multiple times.
    # Non-idempotent (like "Transfer Money") SHOULD NOT.
    # Since we filter by keywords like "transfer", "coupon", we assume non-idempotent.
    
    if success_count > 1:
        unique_statuses = set(status_codes)
        
        # If all requests were successful (e.g. 15 x 200 OK)
        if len(unique_statuses) == 1 and success_count == BATCH_SIZE:
             findings.append({
                "type": "Potential Race Condition (Limit Bypass)",
                "severity": "High",
                "detail": f"Sent {BATCH_SIZE} parallel requests to '{kw}' endpoint, and ALL succeeded.",
                "evidence": f"URL: {url}\nStatus Codes: {status_codes}",
                "remediation": "Implement proper locking (optimistic/pessimistic) for critical transactions."
            })
        
        # If mixed results (some 200, some 429/500/409), protection might be working or partially failing.
        # We focus on the "All Success" case for high confidence.

    return findings

async def run_race_scan(target_url, log_callback=None, headers=None):
    findings = []
    # Race conditions are typically active actions, mostly POST.
    # But some GETs (like /claim?token=...) are vulnearble.
    # We test both if keywords match.
    
    if any(kw in target_url.lower() for kw in RACE_TARGET_KEYWORDS):
        if log_callback: log_callback(f"🏁 Testing Race Conditions on {target_url}...")
        async with aiohttp.ClientSession(headers=headers) as session:
            # Test POST
            res_post = await check_race_condition(session, target_url, method="POST")
            findings.extend(res_post)
            # Test GET if POST yielded nothing? No, let's just stick to checking logic.
            # Actually, GET race conditions are rarer but exist.
            
    return findings
