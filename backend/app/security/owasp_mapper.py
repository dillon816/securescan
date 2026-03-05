# app/security/owasp_mapper.py

from __future__ import annotations

from typing import Optional, Tuple


OWASP_2025 = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging & Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}

# Mapping minimal mais utile (tu pourras enrichir)
CWE_TO_OWASP = {
    # Injection
    78: "A05:2025",   # OS Command Injection
    79: "A05:2025",   # XSS
    89: "A05:2025",   # SQL Injection

    # Access control + SSRF
    285: "A01:2025",
    862: "A01:2025",
    918: "A01:2025",  # SSRF
    200: "A01:2025",

    # Auth
    287: "A07:2025",
    798: "A07:2025",  # hardcoded creds

    # Crypto
    321: "A04:2025",
    326: "A04:2025",
    327: "A04:2025",
    328: "A04:2025",

    # Logging
    532: "A09:2025",
    778: "A09:2025",

    # Exceptions / error handling
    703: "A10:2025",
    754: "A10:2025",
}

KEYWORDS_TO_OWASP = [
    (["sql injection", "command injection", "xss", "injection"], "A05:2025"),
    (["ssrf", "idor", "access control", "unauthorized", "privilege"], "A01:2025"),
    (["authentication", "auth", "jwt", "password", "credential", "hardcoded"], "A07:2025"),
    (["md5", "sha1", "weak crypto", "tls", "ssl", "certificate", "rsa", "ecdsa"], "A04:2025"),
    (["cors", "debug", "misconfig", "exposed", "secret", "token", "api key"], "A02:2025"),
    (["dependency", "package", "composer.lock", "package-lock", "npm", "pip", "supply chain"], "A03:2025"),
    (["deserialize", "signature", "integrity", "tamper"], "A08:2025"),
    (["logging", "log", "alert"], "A09:2025"),
    (["exception", "error handling", "fail open"], "A10:2025"),
]


def map_to_owasp(tool: str, text: str = "", cwe: Optional[int] = None) -> Tuple[str, str]:
    # 1) CWE
    if cwe is not None and cwe in CWE_TO_OWASP:
        o = CWE_TO_OWASP[cwe]
        return o, OWASP_2025[o]

    # 2) Heuristique keywords
    t = (text or "").lower()
    for keys, cat in KEYWORDS_TO_OWASP:
        if any(k in t for k in keys):
            return cat, OWASP_2025[cat]

    # 3) Fallback par outil
    if tool == "trufflehog":
        # TruffleHog = secret exposure → on range en misconfiguration par défaut
        return "A02:2025", OWASP_2025["A02:2025"]

    # Fallback safe
    return "A06:2025", OWASP_2025["A06:2025"]