# app/security/normalizer.py
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from app.security.owasp_mapper import map_to_owasp

"""
Ce module sert à transformer les résultats bruts des outils de scan
(Semgrep, Bandit, TruffleHog) dans un format unique.

Chaque outil renvoie des champs différents.
Ici on les convertit en un format commun utilisé par l'API et la base.
"""


# -------------------------
# Helpers
# -------------------------

def _truncate(text: str, max_len: int = 300) -> str:
    # Coupe un texte trop long pour éviter de stocker des extraits énormes
    if not isinstance(text, str):
        return ""
    text = text.strip()
    if not text:
        return ""
    return text[:max_len] + ("..." if len(text) > max_len else "")


def _severity_normalize(sev: Optional[str]) -> str:
    # Chaque outil utilise ses propres niveaux de sévérité
    # On les convertit vers un format commun
    s = (sev or "").lower().strip()

    if s in ("critical",):
        return "critical"

    if s in ("high", "error"):
        return "high"

    if s in ("medium", "warning", "warn"):
        return "medium"

    # "info" reste "info" pour garder des stats cohérentes
    if s in ("info", "information"):
        return "info"

    if s in ("low",):
        return "low"

    return "unknown"


def _normalize_path(path: str) -> str:
    # Nettoie les chemins de fichiers pour ne garder que le chemin relatif
    # Exemple : src/Controller/... au lieu du chemin Temp complet

    if not isinstance(path, str):
        return ""

    # Normalise les séparateurs Windows
    p = path.replace("\\", "/")

    # Cas ZIP : .../Temp/.../project/...
    marker = "/project/"
    if marker in p:
        p = p.split(marker, 1)[1]

    # Cas Git : .../Temp/.../repo/...
    marker = "/repo/"
    if marker in p:
        p = p.split(marker, 1)[1]

    # Supprime un éventuel préfixe "repo/"
    if p.startswith("repo/"):
        p = p[len("repo/"):]

    return p


def _extract_cwe_semgrep(r: Dict[str, Any]) -> Optional[int]:
    # Semgrep peut renvoyer le CWE sous plusieurs formats
    # Ici on essaye toujours d'obtenir un entier (ex: 502)

    md = (r.get("extra", {}) or {}).get("metadata", {}) or {}
    cwe = md.get("cwe")

    if isinstance(cwe, list) and cwe:
        cwe = cwe[0]

    if isinstance(cwe, str):
        # Exemple : "CWE-502: Deserialization ..."
        cwe_up = cwe.upper()

        if "CWE-" in cwe_up:
            part = cwe_up.split("CWE-", 1)[1].split(":", 1)[0].strip()
            if part.isdigit():
                return int(part)

        # Exemple : "502"
        if cwe.strip().isdigit():
            return int(cwe.strip())

    if isinstance(cwe, int):
        return cwe

    return None
def _extract_owasp_from_semgrep_metadata(r: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    # Semgrep peut fournir une info OWASP directement dans metadata.
    # Exemple: ["A05:2025 - Injection", "A03:2021 - Injection"]
    md = (r.get("extra", {}) or {}).get("metadata", {}) or {}
    owasp = md.get("owasp")

    # Pas d'info OWASP => on laisse None (on fera un mapping heuristique après)
    if not isinstance(owasp, list) or not owasp:
        return None, None

    # On prend en priorité OWASP 2025 si présent
    chosen = None
    for item in owasp:
        if isinstance(item, str) and ":2025" in item:
            chosen = item
            break

    # Sinon on prend la première entrée
    if chosen is None:
        chosen = owasp[0] if isinstance(owasp[0], str) else None

    if not chosen:
        return None, None

    # Format attendu: "A05:2025 - Injection"
    parts = [p.strip() for p in chosen.split("-", 1)]
    if len(parts) == 2:
        return parts[0], parts[1]

    # Si le format est différent, on renvoie juste l'id brut
    return chosen.strip(), None

def normalize_results(tool: str, raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Point d'entrée du normalizer.
    Choisit la fonction adaptée selon l'outil de scan.
    """
    # Normalise le nom de l'outil
    tool = (tool or "").lower().strip()

    # Redirige vers le normalizer correspondant
    if tool == "semgrep":
        return _normalize_semgrep(raw)

    if tool == "bandit":
        return _normalize_bandit(raw)

    if tool == "trufflehog":
        return _normalize_trufflehog(raw)

    # Si l'outil est inconnu on retourne une liste vide
    return []


# -------------------------
# SEMGREP
# -------------------------

def _normalize_semgrep(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Convertit la sortie Semgrep en format standard utilisé par l'application
    issues: List[Dict[str, Any]] = []
    results = raw.get("results", []) or []

    for r in results:

        # Identifiant de la règle Semgrep
        check_id = r.get("check_id") or "semgrep"

        # Bloc extra qui contient message, sévérité, etc.
        extra = r.get("extra", {}) or {}

        # Message descriptif du problème
        message = extra.get("message") or check_id

        # Conversion de la sévérité vers notre format interne
        sev = _severity_normalize(extra.get("severity"))

        # Chemin du fichier dans le projet
        path = _normalize_path(r.get("path") or "")

        # Ligne où le problème commence
        start = (r.get("start") or {}) if isinstance(r.get("start"), dict) else {}
        line = start.get("line")

        # Essaye de récupérer le snippet de code fourni par Semgrep
        lines = extra.get("lines")

        # Si Semgrep renvoie "requires login" on ignore
        if isinstance(lines, str) and lines.strip() and lines.strip().lower() != "requires login":
            snippet = _truncate(lines, 300)
        else:
            snippet = _truncate(str(message), 300)

        # Extraction du CWE si présent dans metadata
        cwe = _extract_cwe_semgrep(r)

        # Si Semgrep fournit OWASP directement on le prend
        owasp_id, owasp_title = _extract_owasp_from_semgrep_metadata(r)

        # Sinon on utilise le mapper OWASP basé sur heuristiques
        if not owasp_id:
            text_for_map = f"{check_id} {message} {snippet}"
            owasp_id, owasp_title = map_to_owasp("semgrep", text=text_for_map, cwe=cwe)

        # Création de l'objet issue normalisé
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
    # Convertit la sortie Bandit en format standard
    issues: List[Dict[str, Any]] = []
    results = raw.get("results", []) or []

    for r in results:

        # Identifiant du test Bandit
        test_id = r.get("test_id") or "bandit"

        # Description du problème
        issue_text = r.get("issue_text") or test_id

        # Normalisation de la sévérité
        severity = _severity_normalize(r.get("issue_severity"))

        # Niveau de confiance du finding
        confidence = (r.get("issue_confidence") or "").lower().strip()

        # Fichier et ligne concernée
        filename = _normalize_path(r.get("filename") or "")
        line = r.get("line_number")

        # Extraction éventuelle du CWE
        cwe = None
        issue_cwe = r.get("issue_cwe")

        if isinstance(issue_cwe, dict):
            cwe_id = issue_cwe.get("id")
            if isinstance(cwe_id, int):
                cwe = cwe_id

        # Snippet du code si Bandit le fournit
        code = r.get("code")
        snippet = issue_text

        if isinstance(code, str) and code.strip():
            snippet = f"{issue_text} | {code.strip()}"

        snippet = _truncate(snippet, 300)

        # Mapping OWASP basé sur texte + CWE
        text_for_map = f"{test_id} {issue_text} {snippet}"
        owasp_id, owasp_title = map_to_owasp("bandit", text=text_for_map, cwe=cwe)

        # Issue normalisée
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
    # Normalise les résultats de TruffleHog (détection de secrets)
    issues: List[Dict[str, Any]] = []
    findings = raw.get("findings", []) or []

    for f in findings:

        # Raison du finding
        reason = f.get("reason") or "Secret detected"

        # Fichier concerné
        path = _normalize_path(f.get("path") or "")

        # Informations liées au commit
        commit_hash = f.get("commitHash")
        date = f.get("date")

        # Essaye de récupérer quelques morceaux détectés
        strings_found = f.get("stringsFound") or []
        snippet = ""

        if isinstance(strings_found, list) and strings_found:
            snippet = ", ".join([str(x) for x in strings_found[:3]])
        else:
            snippet = str(reason)

        # Ajoute un extrait du diff si disponible
        diff = f.get("diff")

        if isinstance(diff, str) and diff.strip():
            snippet = f"{snippet} | diff: {_truncate(diff, 120)}"

        snippet = _truncate(snippet, 300)

        # Mapping OWASP (souvent lié à exposition de secrets)
        text_for_map = f"{reason} {snippet}"
        owasp_id, owasp_title = map_to_owasp("trufflehog", text=text_for_map, cwe=None)

        # Issue finale normalisée
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