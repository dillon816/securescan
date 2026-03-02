import json
import os
import subprocess
from fastapi import HTTPException


def run_bandit(target_dir: str) -> dict:
    """
    Lance Bandit sur target_dir et renvoie un JSON.
    Bandit analyse uniquement les fichiers Python (.py).
    """

    # -r : récursif
    # -f json : format JSON
    # -q : sortie plus silencieuse (pratique pour ne pas polluer stdout)
    cmd = ["bandit", "-r", target_dir, "-f", "json", "-q"]

    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"  # évite des soucis d'encodage Windows

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )

    # Bandit:
    # - returncode 0 : pas de problème bloquant / exécution OK
    # - returncode 1 : findings trouvés (ça reste une exécution OK)
    # - returncode 2+ : erreur d'exécution (commande, droits, etc.)
    if result.returncode not in (0, 1):
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Bandit failed",
                "return_code": result.returncode,
                "stderr_tail": (result.stderr or "")[-2000:],
            },
        )

    # Bandit JSON sort sur stdout
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