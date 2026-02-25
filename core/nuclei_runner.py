"""
Nuclei Template Runner (Pure Python)
Parses and executes Nuclei-compatible YAML templates without requiring the nuclei binary.
Supports HTTP request templates with word, status, and regex matchers.
"""
import os
import re
import asyncio
import aiohttp
import glob

try:
    import yaml
except ImportError:
    yaml = None


class NucleiTemplate:
    """Parsed representation of a Nuclei YAML template."""
    __slots__ = [
        "id", "name", "author", "severity", "description",
        "tags", "reference", "requests",
    ]

    def __init__(self):
        self.id = ""
        self.name = ""
        self.author = ""
        self.severity = "info"
        self.description = ""
        self.tags = []
        self.reference = []
        self.requests = []


class NucleiRequest:
    """A single HTTP request definition from a template."""
    __slots__ = [
        "method", "path", "headers", "body",
        "matchers", "matchers_condition",
        "redirects", "max_redirects",
    ]

    def __init__(self):
        self.method = "GET"
        self.path = ["/"]
        self.headers = {}
        self.body = ""
        self.matchers = []
        self.matchers_condition = "or"  # "and" or "or"
        self.redirects = False
        self.max_redirects = 3


class NucleiMatcher:
    """A matcher condition for response validation."""
    __slots__ = ["type", "words", "status", "regex", "part", "negative", "condition"]

    def __init__(self):
        self.type = "word"  # word, status, regex
        self.words = []
        self.status = []
        self.regex = []
        self.part = "body"  # body, header, all
        self.negative = False
        self.condition = "or"  # "and" or "or"


class NucleiRunner:
    """
    Pure-Python Nuclei template runner.
    
    Usage:
        runner = NucleiRunner(log_callback=print)
        runner.load_templates("templates/nuclei")
        findings = await runner.scan("https://target.com")
    """

    TEMPLATES_DIR = os.path.join(os.getcwd(), "templates", "nuclei")

    def __init__(self, log_callback=None, severity_filter=None):
        self.log = log_callback or (lambda m: None)
        self.templates = []
        self.severity_filter = severity_filter or ["critical", "high", "medium"]

    def load_templates(self, directory=None):
        """Load all YAML templates from directory."""
        if yaml is None:
            self.log("⚠️ PyYAML not installed (pip install pyyaml). Nuclei templates disabled.")
            return 0

        template_dir = directory or self.TEMPLATES_DIR
        os.makedirs(template_dir, exist_ok=True)
        self.templates.clear()

        yaml_files = glob.glob(os.path.join(template_dir, "**", "*.yaml"), recursive=True)
        yaml_files += glob.glob(os.path.join(template_dir, "**", "*.yml"), recursive=True)

        loaded = 0
        for fpath in yaml_files:
            try:
                tpl = self._parse_template(fpath)
                if tpl and tpl.severity.lower() in self.severity_filter:
                    self.templates.append(tpl)
                    loaded += 1
            except Exception as e:
                self.log(f"⚠️ Template parse error ({os.path.basename(fpath)}): {e}")

        if loaded:
            self.log(f"🧬 Loaded {loaded} Nuclei templates from {template_dir}")
        return loaded

    def _parse_template(self, filepath):
        """Parse a single YAML template file."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or "id" not in data:
            return None

        tpl = NucleiTemplate()
        tpl.id = data["id"]

        info = data.get("info", {})
        tpl.name = info.get("name", tpl.id)
        tpl.author = info.get("author", "unknown")
        tpl.severity = info.get("severity", "info")
        tpl.description = info.get("description", "")
        tpl.tags = info.get("tags", "").split(",") if isinstance(info.get("tags"), str) else info.get("tags", [])
        tpl.reference = info.get("reference", [])

        # Parse HTTP requests
        http_list = data.get("http", data.get("requests", []))
        if isinstance(http_list, list):
            for req_data in http_list:
                req = self._parse_request(req_data)
                if req:
                    tpl.requests.append(req)

        return tpl if tpl.requests else None

    def _parse_request(self, data):
        """Parse a single request block from template."""
        if not isinstance(data, dict):
            return None

        req = NucleiRequest()
        req.method = data.get("method", "GET").upper()
        
        paths = data.get("path", ["/"])
        if isinstance(paths, str):
            paths = [paths]
        req.path = paths

        req.headers = data.get("headers", {})
        req.body = data.get("body", "")
        req.redirects = data.get("redirects", False)
        req.max_redirects = data.get("max-redirects", 3)
        req.matchers_condition = data.get("matchers-condition", "or")

        # Parse matchers
        for m_data in data.get("matchers", []):
            matcher = NucleiMatcher()
            matcher.type = m_data.get("type", "word")
            matcher.words = m_data.get("words", [])
            matcher.status = m_data.get("status", [])
            matcher.regex = m_data.get("regex", [])
            matcher.part = m_data.get("part", "body")
            matcher.negative = m_data.get("negative", False)
            matcher.condition = m_data.get("condition", "or")
            req.matchers.append(matcher)

        return req

    async def scan(self, target, session=None, headers=None):
        """Run all loaded templates against a target. Returns list of findings."""
        if not self.templates:
            return []

        findings = []
        own_session = False

        if not session:
            timeout = aiohttp.ClientTimeout(total=15)
            session = aiohttp.ClientSession(timeout=timeout)
            own_session = True

        try:
            self.log(f"🧬 Running {len(self.templates)} Nuclei templates against {target}")

            for tpl in self.templates:
                try:
                    result = await self._execute_template(tpl, target, session, headers)
                    if result:
                        findings.append(result)
                        self.log(f"  🎯 {tpl.severity.upper()}: {tpl.name}")
                except Exception:
                    pass  # Skip individual template errors

            if findings:
                self.log(f"🧬 Nuclei: {len(findings)} findings from {len(self.templates)} templates")

        finally:
            if own_session:
                await session.close()

        return findings

    async def _execute_template(self, tpl, target, session, extra_headers=None):
        """Execute a single template against the target."""
        for req in tpl.requests:
            for path_pattern in req.path:
                # Replace {{BaseURL}} with target
                url = path_pattern.replace("{{BaseURL}}", target.rstrip("/"))
                url = url.replace("{{Hostname}}", target.split("//")[-1].split("/")[0])

                if not url.startswith("http"):
                    url = target.rstrip("/") + url

                # Build headers
                hdrs = {}
                if extra_headers:
                    hdrs.update(extra_headers)
                hdrs.update(req.headers)

                try:
                    allow_redirects = req.redirects
                    async with session.request(
                        req.method, url,
                        headers=hdrs,
                        data=req.body if req.body else None,
                        ssl=False,
                        allow_redirects=allow_redirects,
                        max_redirects=req.max_redirects if allow_redirects else 0,
                    ) as resp:
                        status = resp.status
                        resp_headers = dict(resp.headers)
                        body = await resp.text(errors="replace")

                        # Check matchers
                        matched = self._check_matchers(
                            req.matchers, req.matchers_condition,
                            status, resp_headers, body
                        )

                        if matched:
                            return {
                                "type": f"Nuclei: {tpl.name}",
                                "severity": self._normalize_severity(tpl.severity),
                                "detail": tpl.description or f"Detected by Nuclei template: {tpl.id}",
                                "url": url,
                                "evidence": f"Template: {tpl.id}\nStatus: {status}\nMatched via {req.matchers_condition} condition",
                                "remediation": f"Refer to: {', '.join(tpl.reference) if tpl.reference else 'N/A'}",
                                "cwe": "",
                                "nuclei_template_id": tpl.id,
                                "nuclei_tags": tpl.tags,
                            }
                except asyncio.TimeoutError:
                    pass
                except Exception:
                    pass

        return None

    def _check_matchers(self, matchers, condition, status, headers, body):
        """Evaluate matcher conditions against response."""
        if not matchers:
            return False

        results = []

        for matcher in matchers:
            matched = self._evaluate_matcher(matcher, status, headers, body)
            if matcher.negative:
                matched = not matched
            results.append(matched)

        if condition == "and":
            return all(results)
        else:
            return any(results)

    def _evaluate_matcher(self, matcher, status, headers, body):
        """Evaluate a single matcher."""
        target_text = ""
        if matcher.part == "body":
            target_text = body
        elif matcher.part == "header":
            target_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
        elif matcher.part == "all":
            target_text = "\n".join(f"{k}: {v}" for k, v in headers.items()) + "\n" + body

        if matcher.type == "status":
            return status in matcher.status

        elif matcher.type == "word":
            if matcher.condition == "and":
                return all(w.lower() in target_text.lower() for w in matcher.words)
            else:
                return any(w.lower() in target_text.lower() for w in matcher.words)

        elif matcher.type == "regex":
            for pattern in matcher.regex:
                try:
                    if re.search(pattern, target_text, re.I | re.S):
                        return True
                except re.error:
                    pass
            return False

        return False

    def _normalize_severity(self, sev):
        """Map Nuclei severity to LOCKON severity."""
        mapping = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Info",
        }
        return mapping.get(sev.lower(), "Info")


async def run_nuclei_templates(target, log_callback=None, headers=None):
    """Entry point for scanner integration."""
    runner = NucleiRunner(log_callback=log_callback)
    count = runner.load_templates()
    if count == 0:
        return []
    return await runner.scan(target, headers=headers)
