"""
Scope Manager
Ensures scanner stays within defined target boundaries.
"""
import re
from urllib.parse import urlparse

class ScopeManager:
    """Manages in-scope and out-of-scope URL patterns for scanning."""
    
    def __init__(self, base_target=""):
        self.base_target = base_target
        self.include_patterns = []  # Wildcard patterns to include
        self.exclude_patterns = []  # Wildcard patterns to exclude
        self._base_domain = ""
        
        if base_target:
            parsed = urlparse(base_target if "://" in base_target else f"https://{base_target}")
            self._base_domain = parsed.hostname or ""
    
    def set_patterns(self, includes="", excludes=""):
        """Set include/exclude patterns from comma-separated strings.
        
        Patterns support wildcards:
        - *.example.com → matches sub.example.com
        - /api/* → matches /api/users, /api/orders
        - /admin/delete* → matches /admin/delete, /admin/delete-all
        """
        self.include_patterns = [p.strip() for p in includes.split(",") if p.strip()] if includes else []
        self.exclude_patterns = [p.strip() for p in excludes.split(",") if p.strip()] if excludes else []
    
    def _wildcard_to_regex(self, pattern):
        """Convert wildcard pattern to regex."""
        escaped = re.escape(pattern)
        return escaped.replace(r"\*", ".*")
    
    def _matches_pattern(self, url, pattern):
        """Check if URL matches a wildcard pattern."""
        regex = self._wildcard_to_regex(pattern)
        
        # If pattern looks like a path (starts with /), match against URL path
        if pattern.startswith("/"):
            parsed = urlparse(url)
            return bool(re.match(regex, parsed.path, re.IGNORECASE))
        
        # Otherwise match against the full URL or hostname
        parsed = urlparse(url if "://" in url else f"https://{url}")
        hostname = parsed.hostname or ""
        
        return (
            bool(re.match(regex, url, re.IGNORECASE)) or
            bool(re.match(regex, hostname, re.IGNORECASE))
        )
    
    def is_in_scope(self, url):
        """Check if a URL is within the defined scope.
        
        Rules:
        1. If exclude patterns are defined and URL matches any → OUT of scope
        2. If include patterns are defined and URL matches any → IN scope
        3. If no include patterns, URL must match base target domain → IN scope
        4. Otherwise → OUT of scope
        """
        if not url:
            return False
        
        # Check excludes first (highest priority)
        for pattern in self.exclude_patterns:
            if self._matches_pattern(url, pattern):
                return False
        
        # Check includes
        if self.include_patterns:
            for pattern in self.include_patterns:
                if self._matches_pattern(url, pattern):
                    return True
            return False  # Include patterns defined but none matched
        
        # Default: must be same domain as base target
        if self._base_domain:
            parsed = urlparse(url if "://" in url else f"https://{url}")
            hostname = parsed.hostname or ""
            return hostname == self._base_domain or hostname.endswith(f".{self._base_domain}")
        
        return True  # No restrictions if no base target
    
    @property
    def is_configured(self):
        """Returns True if any scope rules are configured."""
        return bool(self.include_patterns or self.exclude_patterns)
