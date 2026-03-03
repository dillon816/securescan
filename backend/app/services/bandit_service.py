import json
import os
import subprocess
import sys
from fastapi import HTTPException


def run_bandit(target_dir: str) -> dict:
    """
    Lance Bandit sur target_dir et renvoie un JSON.
    Bandit analyse uniquement les fichiers Python (.py).

    Stratégie:
    - tente "bandit ..."
    - sinon fallback "python -m bandit ..."
    """

    args = ["-r", target_dir, "-f", "json", "-q"]

    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"

    # 1) tente bandit
    cmd = ["bandit"] + args
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
        # 2) fallback python -m bandit (venv)
        cmd = [sys.executable, "-m", "bandit"] + args
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )

    # Bandit:
    # 0 = ok (no findings)
    # 1 = ok (findings)
    # 2+ = error
    if result.returncode not in (0, 1):
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Bandit failed",
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
                "error": "Cannot parse Bandit JSON",
                "stdout_sample": (result.stdout or "")[:2000],
                "stderr_sample": (result.stderr or "")[:2000],
            },
        )