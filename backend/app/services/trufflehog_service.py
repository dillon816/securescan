import json
import re
import subprocess

import shutil

TRUFFLEHOG_BIN = shutil.which("trufflehog") or "trufflehog"

# Supprime les codes couleurs ANSI éventuels
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text or "")


def _normalize_finding(finding: dict) -> dict:
    # Nettoyage des champs texte
    if "printDiff" in finding and isinstance(finding["printDiff"], str):
        finding["printDiff"] = _strip_ansi(finding["printDiff"])

    if "diff" in finding and isinstance(finding["diff"], str):
        finding["diff"] = _strip_ansi(finding["diff"])

    # Evite les réponses énormes + fuite de données (SQL dump, composer.lock, etc.)
    finding.pop("diff", None)
    finding.pop("printDiff", None)

    # Limite stringsFound pour rester lisible
    if isinstance(finding.get("stringsFound"), list):
        finding["stringsFound"] = finding["stringsFound"][:3]

    # Normalisation du chemin
    path = finding.get("path")
    if isinstance(path, str):
        path = path.replace("\\", "/")
        if path.startswith("repo/"):
            path = path[len("repo/"):]
        finding["path"] = path

    return finding


def run_trufflehog(target: str) -> dict:
    normalized_target = target.replace('\\', '/')
    cmd = [TRUFFLEHOG_BIN, "--json", "filesystem", normalized_target]

    process = subprocess.run(cmd, capture_output=True, text=True)
    stdout = (process.stdout or "").strip()
    stderr = (process.stderr or "").strip()

    findings = []

    # Ancien TruffleHog renvoie 1 JSON par ligne
    if stdout:
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    findings.append(_normalize_finding(data))
            except json.JSONDecodeError:
                pass

    # Bug Windows cleanup
    cleanup_issue = (
        ("PermissionError" in stderr or "WinError 32" in stderr or "WinError 5" in stderr)
        and ("truffleHog.py" in stderr or "shutil.rmtree" in stderr or "del_rw" in stderr)
    )

    # Scan OK mais cleanup KO
    if process.returncode != 0 and cleanup_issue:
        return {
            "ok": True,
            "status": "warning",
            "non_fatal": True,
            "return_code": process.returncode,
            "cmd": cmd,
            "warning": "TruffleHog cleanup failed on Windows (ignored).",
            "findings": findings,
            "stderr_tail": stderr[-300:],
        }

    # Vrai échec
    if process.returncode != 0:
        return {
            "ok": False,
            "status": "error",
            "non_fatal": False,
            "error": "TruffleHog failed",
            "return_code": process.returncode,
            "cmd": cmd,
            "stderr_tail": stderr[-1000:],
        }

    return {
        "ok": True,
        "status": "ok",
        "non_fatal": False,
        "return_code": 0,
        "cmd": cmd,
        "findings": findings,
    }