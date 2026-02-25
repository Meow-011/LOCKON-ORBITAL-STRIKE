"""
False Positive Validator
Assigns confidence scores to findings via heuristics and optional re-validation.
"""
import re
import asyncio
import aiohttp
import time


# Heuristic weight table per finding type pattern
# Each rule returns a confidence delta (-30 to +40)
_HEURISTIC_RULES = {
    # --- SQL Injection ---
    "SQL Injection": [
        ("evidence_has_sql_error", 30, "SQL error string in response confirms injection"),
        ("evidence_has_time_delay", 25, "Time-based blind confirmed via measurable delay"),
        ("multiple_payloads_work", 20, "Multiple distinct payloads triggered the same behaviour"),
        ("generic_error_only", -20, "Only a generic error page, may be WAF/framework default"),
    ],
    # --- XSS ---
    "XSS": [
        ("payload_reflected_unencoded", 35, "Payload appears unencoded in response body"),
        ("dom_sink_detected", 20, "Known DOM sink matches the reflected context"),
        ("csp_blocks_execution", -25, "Strong CSP header would prevent exploitation"),
        ("reflected_in_attribute", 15, "Reflected inside an HTML attribute value"),
    ],
    # --- LFI / Path Traversal ---
    "LFI": [
        ("etc_passwd_content", 40, "Response contains /etc/passwd content (root:)"),
        ("windows_ini_content", 40, "Response contains [extensions] or win.ini markers"),
        ("path_in_error", -15, "Traversal path visible in error but no file content"),
    ],
    "Path Traversal": [
        ("etc_passwd_content", 40, "Contains /etc/passwd entries"),
        ("windows_ini_content", 40, "Contains win.ini markers"),
    ],
    # --- SSRF ---
    "SSRF": [
        ("oob_callback_received", 40, "Out-of-band callback confirmed"),
        ("internal_ip_in_response", 25, "Internal IP/metadata in response body"),
        ("timeout_difference", 15, "Timing side-channel suggests internal reach"),
    ],
    # --- SSTI ---
    "SSTI": [
        ("math_result_confirmed", 35, "Template expression evaluated (e.g. 7*7=49)"),
        ("multiple_engines_tested", 15, "Tested across multiple template syntaxes"),
    ],
    # --- Command Injection ---
    "Command Injection": [
        ("command_output_in_body", 35, "OS command output visible in response"),
        ("time_delay_confirmed", 25, "Sleep/ping delay confirmed via timing"),
    ],
    "OS Command Injection": [
        ("command_output_in_body", 35, "OS command output visible in response"),
        ("time_delay_confirmed", 25, "Sleep/ping delay confirmed via timing"),
    ],
}

# Patterns for heuristic checks
_PATTERNS = {
    "sql_errors": re.compile(
        r"(SQL syntax|mysql_|ORA-\d|PG::SyntaxError|sqlite3\.|"
        r"Unclosed quotation|quoted string not properly terminated|"
        r"Microsoft OLE DB|ODBC SQL Server Driver|"
        r"com\.mysql\.jdbc|org\.postgresql)", re.I
    ),
    "etc_passwd": re.compile(r"root:[x*]:0:0:", re.I),
    "win_ini": re.compile(r"\[extensions\]|\[fonts\]|for 16-bit app support", re.I),
    "internal_ip": re.compile(r"(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.169\.254)"),
    "math_49": re.compile(r"\b49\b"),
    "csp_header": re.compile(r"script-src\s+((?!unsafe-inline|unsafe-eval|\*))", re.I),
    "xss_unencoded": re.compile(r"<script>|onerror\s*=|onload\s*=|javascript:", re.I),
    "dom_sinks": re.compile(r"(innerHTML|document\.write|\.html\(|eval\(|setTimeout\(|setInterval\()", re.I),
}


class FPValidator:
    """Assigns confidence scores to findings and optionally re-validates."""

    CONFIDENCE_HIGH = "HIGH"       # 80-100
    CONFIDENCE_MEDIUM = "MEDIUM"   # 50-79
    CONFIDENCE_LOW = "LOW"         # 0-49

    def __init__(self, log_callback=None, session=None):
        self.log = log_callback or (lambda m: None)
        self.session = session  # aiohttp.ClientSession for re-validation

    def score_finding(self, finding):
        """
        Assign a confidence score to a finding based on heuristics.
        Modifies the finding dict in-place, adding 'confidence' and 'confidence_label'.
        Returns the confidence score (0-100).
        """
        base_score = 50  # Start at 50% (neutral)
        reasons = []
        ftype = finding.get("type", "")
        evidence = str(finding.get("evidence", "")) + str(finding.get("detail", ""))
        severity = finding.get("severity", "Info")

        # --- Severity baseline ---
        sev_bonus = {"Critical": 15, "High": 10, "Medium": 5, "Low": 0, "Info": -10}
        base_score += sev_bonus.get(severity, 0)
        
        # --- Evidence quality ---
        if finding.get("evidence"):
            ev_len = len(str(finding["evidence"]))
            if ev_len > 200:
                base_score += 10
                reasons.append("Rich evidence body")
            elif ev_len > 50:
                base_score += 5
        
        # --- Type-specific heuristics ---
        matched_rules = self._find_matching_rules(ftype)
        for rule_id, delta, desc in matched_rules:
            triggered = self._check_rule(rule_id, finding, evidence)
            if triggered:
                base_score += delta
                reasons.append(f"{'+' if delta > 0 else ''}{delta}: {desc}")

        # --- CVSS correlation ---
        cvss = finding.get("cvss_score", 0)
        if cvss >= 9.0:
            base_score += 5
        elif cvss <= 3.0 and severity in ("High", "Critical"):
            base_score -= 10
            reasons.append("-10: Severity/CVSS mismatch")

        # --- Clamp to 0-100 ---
        confidence = max(0, min(100, base_score))

        # --- Label ---
        if confidence >= 80:
            label = self.CONFIDENCE_HIGH
        elif confidence >= 50:
            label = self.CONFIDENCE_MEDIUM
        else:
            label = self.CONFIDENCE_LOW

        # --- Enrich finding ---
        finding["confidence"] = confidence
        finding["confidence_label"] = label
        finding["confidence_reasons"] = reasons

        return confidence

    def _find_matching_rules(self, ftype):
        """Find heuristic rules that match the finding type."""
        rules = []
        for pattern, rule_list in _HEURISTIC_RULES.items():
            if pattern.lower() in ftype.lower():
                rules.extend(rule_list)
        return rules

    def _check_rule(self, rule_id, finding, evidence):
        """Evaluate a single heuristic rule."""
        if rule_id == "evidence_has_sql_error":
            return bool(_PATTERNS["sql_errors"].search(evidence))
        
        elif rule_id == "evidence_has_time_delay":
            return "time" in evidence.lower() and ("delay" in evidence.lower() or "sleep" in evidence.lower())
        
        elif rule_id == "multiple_payloads_work":
            return evidence.count("payload") >= 2 or evidence.count("Sent:") >= 2
        
        elif rule_id == "generic_error_only":
            return ("error" in evidence.lower() or "500" in evidence) and not _PATTERNS["sql_errors"].search(evidence)
        
        elif rule_id == "payload_reflected_unencoded":
            return bool(_PATTERNS["xss_unencoded"].search(evidence))
        
        elif rule_id == "dom_sink_detected":
            return bool(_PATTERNS["dom_sinks"].search(evidence))
        
        elif rule_id == "csp_blocks_execution":
            resp_headers = str(finding.get("response_headers", ""))
            return bool(_PATTERNS["csp_header"].search(resp_headers))
        
        elif rule_id == "reflected_in_attribute":
            return 'value="' in evidence or "value='" in evidence
        
        elif rule_id == "etc_passwd_content":
            return bool(_PATTERNS["etc_passwd"].search(evidence))
        
        elif rule_id == "windows_ini_content":
            return bool(_PATTERNS["win_ini"].search(evidence))
        
        elif rule_id == "path_in_error":
            return ("../" in evidence or "..\\" in evidence) and not _PATTERNS["etc_passwd"].search(evidence)
        
        elif rule_id == "oob_callback_received":
            return "callback" in evidence.lower() or "dns" in evidence.lower() or "oast" in evidence.lower()
        
        elif rule_id == "internal_ip_in_response":
            return bool(_PATTERNS["internal_ip"].search(evidence))
        
        elif rule_id == "timeout_difference":
            return "timeout" in evidence.lower() or "delay" in evidence.lower()
        
        elif rule_id == "math_result_confirmed":
            return bool(_PATTERNS["math_49"].search(evidence)) and "{{" in str(finding.get("detail", ""))
        
        elif rule_id == "multiple_engines_tested":
            return evidence.count("{{") >= 2 or evidence.count("${") >= 2
        
        elif rule_id == "command_output_in_body":
            return any(kw in evidence.lower() for kw in ["uid=", "root", "www-data", "windows", "volume serial"])
        
        elif rule_id == "time_delay_confirmed":
            return "sleep" in evidence.lower() or "ping" in evidence.lower()

        return False

    async def revalidate(self, finding, headers=None):
        """
        Re-send the triggering request to see if the finding is reproducible.
        Adds 'revalidated' and 'revalidation_result' fields.
        """
        url = finding.get("url")
        if not url or not self.session:
            return finding

        try:
            async with self.session.get(url, headers=headers, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                body = await resp.text(errors="replace")
                evidence = str(finding.get("evidence", ""))

                # Check if the original evidence pattern still exists
                reproduced = False
                if _PATTERNS["sql_errors"].search(body) and "SQL" in finding.get("type", ""):
                    reproduced = True
                elif _PATTERNS["xss_unencoded"].search(body) and "XSS" in finding.get("type", ""):
                    reproduced = True
                elif _PATTERNS["etc_passwd"].search(body) and ("LFI" in finding.get("type", "") or "Path" in finding.get("type", "")):
                    reproduced = True

                finding["revalidated"] = True
                finding["revalidation_result"] = "CONFIRMED" if reproduced else "UNCONFIRMED"

                if reproduced:
                    finding["confidence"] = min(100, finding.get("confidence", 50) + 15)
                else:
                    finding["confidence"] = max(0, finding.get("confidence", 50) - 20)

                # Update label
                c = finding["confidence"]
                finding["confidence_label"] = (
                    self.CONFIDENCE_HIGH if c >= 80 else
                    self.CONFIDENCE_MEDIUM if c >= 50 else
                    self.CONFIDENCE_LOW
                )

        except Exception:
            finding["revalidated"] = False
            finding["revalidation_result"] = "ERROR"

        return finding

    def batch_score(self, findings):
        """Score a list of findings. Returns stats dict."""
        stats = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            self.score_finding(f)
            stats[f["confidence_label"]] += 1
        return stats
