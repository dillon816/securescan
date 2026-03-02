import json
import os
import subprocess
import sys
from pathlib import Path
from fastapi import HTTPException


def run_semgrep(target_dir: str) -> dict:
    """
    Lance Semgrep sur le dossier `target_dir` et renvoie le JSON parsé.

    Stratégie :
    - On essaie d'abord la commande `semgrep` (si dispo dans le PATH)
    - Sinon, on fallback sur `python -m semgrep` via l'interpréteur du venv (sys.executable)
    """

    repo_path = Path(target_dir).resolve()
    if not repo_path.exists() or not repo_path.is_dir():
        raise HTTPException(
            status_code=400,
            detail={"error": "target_dir must be an existing directory", "target_dir": str(repo_path)},
        )

    # Arguments Semgrep (scan + rules auto + JSON)
    args = ["scan", "--config", "auto", "--json", str(repo_path)]

    # 1) On tente "semgrep ..."
    cmd = ["semgrep"] + args

    # Sur Windows, l'encodage peut faire planter des outputs (charmap)
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
    except FileNotFoundError:
        # 2) Fallback : python -m semgrep (interpréteur du venv)
        cmd = [sys.executable, "-m", "semgrep"] + args
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )

    # Semgrep peut renvoyer 1 si findings => on accepte 0 et 1
    if result.returncode not in (0, 1):
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Semgrep failed",
                "return_code": result.returncode,
                "stderr_tail": (result.stderr or "")[-2000:],
            },
        )

    try:
        return json.loads(result.stdout or "{}")
    except Exception:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Cannot parse Semgrep JSON",
                "stdout_sample": (result.stdout or "")[:2000],
                "stderr_sample": (result.stderr or "")[:2000],
            },
        )