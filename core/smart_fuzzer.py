import re
from urllib.parse import urlparse, parse_qs

class SmartFuzzer:
    """
    Core AI/Heuristic Brain for the Scanner.
    Analyzes targets to determine the most effective attack vectors,
    reducing noise and increasing efficiency.
    """

    PATTERNS = {
        'id_numeric': re.compile(r'^[0-9]+$'),
        'uuid': re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I),
        'file_ext': re.compile(r'\.(php|asp|aspx|jsp|html|js)$', re.I),
        'path_traversal': re.compile(r'(=[\w\-\.]+(/|\\))'), # param=something/
        'email': re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$'),
        'json_like': re.compile(r'^\{.*\}$|^\[.*\]$'),
        'base64': re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
    }

    @staticmethod
    def analyze_param(name, value):
        tags = set()
        
        # 1. ID Analysis
        if any(x in name.lower() for x in ['id', 'user', 'account', 'order', 'item']):
            tags.add('is_identifier')
            if SmartFuzzer.PATTERNS['id_numeric'].match(value):
                tags.add('type_integer')
            elif SmartFuzzer.PATTERNS['uuid'].match(value):
                tags.add('type_uuid')
        
        # 2. File/Path Analysis
        if any(x in name.lower() for x in ['file', 'path', 'doc', 'img', 'dir', 'folder']):
            tags.add('is_path')
        if SmartFuzzer.PATTERNS['file_ext'].search(value) or '/' in value or '\\' in value:
            tags.add('is_path')
            
        # 3. Code/Command Analysis
        if any(x in name.lower() for x in ['cmd', 'exec', 'command', 'ping', 'query']):
            tags.add('is_command')
            
        # 4. Redirect Analysis
        if any(x in name.lower() for x in ['url', 'redirect', 'next', 'goto', 'link', 'dest']):
            tags.add('is_redirect')
            
        return tags

    @staticmethod
    def get_attack_plan(url):
        """
        Returns a set of recommended attack modules for the given URL.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        plan = set()
        
        # Always run basics
        plan.add('headers')
        
        if not params:
            # Check for REST Path Vectors
            path_segments = parsed.path.strip("/").split("/")
            for segment in path_segments:
                if not segment: continue
                
                # Treat segment as a value
                tags = SmartFuzzer.analyze_param("path_segment", segment)
                
                if 'type_integer' in tags or 'type_uuid' in tags:
                    plan.add('bola')
                    plan.add('nosql')
                    plan.add('sqli') # REST ID SQLi
                    
                if 'is_command' in tags:
                    plan.add('rce')
                    
            # Still no plan? Add basics for safety
            if not plan:
                plan.add('headers')
                # Maybe simple fuzzing?
                
            return plan

        # Analyze Parameters
        for name, values in params.items():
            for value in values:
                tags = SmartFuzzer.analyze_param(name, value)
                
                # [STRATEGY DECISION MATRIX]
                
                # Numeric IDs -> SQLi, BOLA, IDOR
                if 'is_identifier' in tags and 'type_integer' in tags:
                    plan.add('sqli')
                    plan.add('nosql')
                    plan.add('bola')
                    plan.add('idor')
                
                # UUIDs -> NoSQL, BOLA (SQLi less likely but possible)
                if 'type_uuid' in tags:
                    plan.add('nosql')
                    plan.add('bola')
                
                # Path/File -> LFI, RCE, Path Traversal
                if 'is_path' in tags:
                    plan.add('lfi')
                    plan.add('rce')
                    plan.add('traversal')
                
                # Command -> RCE
                if 'is_command' in tags:
                    plan.add('rce')
                    
                # Redirect -> Open Redirect, SSRF
                if 'is_redirect' in tags:
                    plan.add('redirect')
                    plan.add('ssrf')

                # General Injection for all params
                plan.add('xss') 
                plan.add('ssti')
        
        # [NEW] Mix Path Analysis with Param Analysis
        # Some path segments might be interesting even if params exist
        path_segments = parsed.path.strip("/").split("/")
        for segment in path_segments:
             if SmartFuzzer.PATTERNS['id_numeric'].match(segment):
                 plan.add('bola') # High chance of ID in path
        
        return plan
