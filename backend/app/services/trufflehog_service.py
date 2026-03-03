import json
import os
import subprocess
import sys
from fastapi import HTTPException


def run_trufflehog(target_dir: str) -> dict:
    """
    Lance TruffleHog v2 (pip package trufflehog==2.x) sur un repo local et renvoie un JSON.
    TruffleHog v2 renvoie 1 JSON par ligne en mode --json.
    """

    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"

    # TruffleHog v2 syntaxe : trufflehog --json <repo_path>
    cmd = ["trufflehog", "--json", target_dir]

    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
    except FileNotFoundError:
        # Fallback si le binaire "trufflehog" n'est pas dans le PATH
        cmd = [sys.executable, "-m", "trufflehog", "--json", target_dir]
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )

    stdout = process.stdout or ""
    stderr = process.stderr or ""

    # TruffleHog v2: 1 JSON par ligne
    findings = []
    for line in stdout.splitlines():
        line = (line or "").strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                findings.append(data)
        except json.JSONDecodeError:
            # ignore les lignes non json
            pass

    # Si rien en stdout ET code != 0 => vrai échec
    if not findings and process.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "TruffleHog failed",
                "return_code": process.returncode,
                "stderr_tail": stderr[-2000:],
            },
        )

    return {
        "findings": findings,
        "return_code": process.returncode,
        "stderr_tail": stderr[-2000:],
    }