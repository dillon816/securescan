# app/security/normalizer.py
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from app.security.owasp_mapper import map_to_owasp


# -------------------------
# Helpers
# -------------------------

def _truncate(text: str, max_len: int = 300) -> str:
    if not isinstance(text, str):
        return ""
    text = text.strip()
    if not text:
        return ""
    return text[:max_len] + ("..." if len(text) > max_len else "")


def _severity_normalize(sev: Optional[str]) -> str:
    s = (sev or "").lower().strip()
    if s in ("critical",):
        return "critical"
    if s in ("high", "error"):
        return "high"
    if s in ("medium", "warning", "warn"):
        return "medium"
    if s in ("low", "info", "information"):
        return "low"
    return "unknown"


def _normalize_path(path: str) -> str:
    """
    Rend les paths plus lisibles:
    - remplace \\ par /
    - retire tout ce qui est .../Temp/.../project/ ou .../Temp/.../repo/
    - retire prefix "repo/"
    """
    if not isinstance(path, str):
        return ""
    p = path.replace("\\", "/")

    # cas ZIP: .../Temp/<id>/project/<...>
    marker = "/project/"
    if marker in p:
        p = p.split(marker, 1)[1]

    # cas GIT: .../Temp/<id>/repo/<...>
    marker = "/repo/"
    if marker in p:
        p = p.split(marker, 1)[1]

    if p.startswith("repo/"):
        p = p[len("repo/"):]
    return p


def _extract_cwe_semgrep(r: Dict[str, Any]) -> Optional[int]:
    md = (r.get("extra", {}) or {}).get("metadata", {}) or {}
    cwe = md.get("cwe")
    if isinstance(cwe, list) and cwe:
        cwe = cwe[0]

    if isinstance(cwe, str):
        # ex: "CWE-502: Deserialization of Untrusted Data"
        cwe_up = cwe.upper()
        if "CWE-" in cwe_up:
            part = cwe_up.split("CWE-", 1)[1].split(":", 1)[0].strip()
            if part.isdigit():
                return int(part)
        # ex: "502"
        if cwe.strip().isdigit():
            return int(cwe.strip())

    if isinstance(cwe, int):
        return cwe

    return None


def _extract_owasp_from_semgrep_metadata(r: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """
    Semgrep met souvent une liste style:
      ["A05:2025 - Injection", "A03:2021 - Injection", ...]
    On prend en priorité une entrée 2025, sinon la première.
    """
    md = (r.get("extra", {}) or {}).get("metadata", {}) or {}
    owasp = md.get("owasp")

    if not isinstance(owasp, list) or not owasp:
        return None, None

    chosen = None
    for item in owasp:
        if isinstance(item, str) and ":2025" in item:
            chosen = item
            break
    if chosen is None:
        chosen = owasp[0] if isinstance(owasp[0], str) else None

    if not chosen:
        return None, None

    # parse "A05:2025 - Injection"
    parts = [p.strip() for p in chosen.split("-", 1)]
    if len(parts) == 2:
        return parts[0], parts[1]
    return chosen.strip(), None


def normalize_results(tool: str, raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    tool = (tool or "").lower().strip()

    if tool == "semgrep":
        return _normalize_semgrep(raw)

    if tool == "bandit":
        return _normalize_bandit(raw)

    if tool == "trufflehog":
        return _normalize_trufflehog(raw)

    return []


# -------------------------
# SEMGREP
# -------------------------

def _normalize_semgrep(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    results = raw.get("results", []) or []

    for r in results:
        check_id = r.get("check_id") or "semgrep"
        extra = r.get("extra", {}) or {}
        message = extra.get("message") or check_id

        sev = _severity_normalize(extra.get("severity"))

        path = _normalize_path(r.get("path") or "")
        start = (r.get("start") or {}) if isinstance(r.get("start"), dict) else {}
        line = start.get("line")

        lines = extra.get("lines")
        # Semgrep OSS met parfois "requires login" => on ignore
        if isinstance(lines, str) and lines.strip() and lines.strip().lower() != "requires login":
            snippet = _truncate(lines, 300)
        else:
            snippet = _truncate(str(message), 300)

        cwe = _extract_cwe_semgrep(r)

        # ✅ Si Semgrep fournit déjà OWASP dans metadata, on prend ça (plus fiable)
        owasp_id, owasp_title = _extract_owasp_from_semgrep_metadata(r)
        if not owasp_id:
            text_for_map = f"{check_id} {message} {snippet}"
            owasp_id, owasp_title = map_to_owasp("semgrep", text=text_for_map, cwe=cwe)

        issues.append({
            "tool": "semgrep",
            "rule_id": check_id,
            "title": str(message),
            "severity": sev,
            "file": path,
            "line": line,
            "snippet": snippet,
            "owasp_id": owasp_id,
            "owasp_title": owasp_title,
        })

    return issues


# -------------------------
# BANDIT
# -------------------------

def _normalize_bandit(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    results = raw.get("results", []) or []

    for r in results:
        test_id = r.get("test_id") or "bandit"
        issue_text = r.get("issue_text") or test_id
        severity = _severity_normalize(r.get("issue_severity"))
        confidence = (r.get("issue_confidence") or "").lower().strip()

        filename = _normalize_path(r.get("filename") or "")
        line = r.get("line_number")

        # ✅ Bandit donne souvent un CWE id numérique: r["issue_cwe"]["id"]
        cwe = None
        issue_cwe = r.get("issue_cwe")
        if isinstance(issue_cwe, dict):
            cwe_id = issue_cwe.get("id")
            if isinstance(cwe_id, int):
                cwe = cwe_id

        code = r.get("code")
        snippet = issue_text
        if isinstance(code, str) and code.strip():
            snippet = f"{issue_text} | {code.strip()}"
        snippet = _truncate(snippet, 300)

        text_for_map = f"{test_id} {issue_text} {snippet}"
        owasp_id, owasp_title = map_to_owasp("bandit", text=text_for_map, cwe=cwe)

        issues.append({
            "tool": "bandit",
            "rule_id": test_id,
            "title": issue_text,
            "severity": severity,
            "confidence": confidence or None,
            "file": filename,
            "line": line,
            "snippet": snippet,
            "owasp_id": owasp_id,
            "owasp_title": owasp_title,
        })

    return issues


# -------------------------
# TRUFFLEHOG
# -------------------------

def _normalize_trufflehog(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    findings = raw.get("findings", []) or []

    for f in findings:
        reason = f.get("reason") or "Secret detected"
        path = _normalize_path(f.get("path") or "")
        commit_hash = f.get("commitHash")
        date = f.get("date")

        strings_found = f.get("stringsFound") or []
        snippet = ""
        if isinstance(strings_found, list) and strings_found:
            # max 3 éléments lisibles
            snippet = ", ".join([str(x) for x in strings_found[:3]])
        else:
            snippet = str(reason)

        # si tu veux, tu peux aussi afficher un mini bout de diff (mais pas énorme)
        diff = f.get("diff")
        if isinstance(diff, str) and diff.strip():
            snippet = f"{snippet} | diff: {_truncate(diff, 120)}"

        snippet = _truncate(snippet, 300)

        text_for_map = f"{reason} {snippet}"
        owasp_id, owasp_title = map_to_owasp("trufflehog", text=text_for_map, cwe=None)

        issues.append({
            "tool": "trufflehog",
            "rule_id": reason,
            "title": "Secret detected",
            "severity": "high",
            "file": path,
            "line": None,
            "snippet": snippet,
            "commit": commit_hash,
            "date": date,
            "owasp_id": owasp_id,
            "owasp_title": owasp_title,
        })

    return issues