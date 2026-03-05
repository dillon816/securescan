import json
import os
import subprocess
import sys
from pathlib import Path
from fastapi import HTTPException
 
 
def run_semgrep(target_dir: str) -> dict:
    """
    Lance Semgrep sur le dossier `target_dir` et renvoie le JSON parsé.
 
    - On essaie d'abord la commande `semgrep` (si dispo dans le PATH)
    - Sinon, on fallback sur `python -m semgrep` via l'interpréteur du venv (sys.executable)
    """
 
    repo_path = Path(target_dir).resolve()
    if not repo_path.exists() or not repo_path.is_dir():
        raise HTTPException(
            status_code=400,
            detail={"error": "target_dir must be an existing directory", "target_dir": str(repo_path)},
        )
 
    # Arguments Semgrep
    args = ["scan", "--config", "p/owasp-top-ten", "--json", str(repo_path)]

    # Sur Windows, l'encodage peut faire planter des outputs (charmap)
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    # Ajoute le chemin Python au PATH pour trouver semgrep
    python_bin_dir = Path.home() / "Library" / "Python" / "3.9" / "bin"
    if python_bin_dir.exists():
        env["PATH"] = str(python_bin_dir) + ":" + env.get("PATH", "")

    # 1) On tente "semgrep ..." directement (recommandé)
    cmd = ["semgrep"] + args
    
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
        # 2) Si semgrep n'est pas dans PATH, utilise le chemin complet
        semgrep_bin = python_bin_dir / "semgrep"
        if semgrep_bin.exists():
            cmd = [str(semgrep_bin)] + args
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
            )
        else:
            # 3) Dernier recours : python -m semgrep (mais ne retourne pas de JSON)
            cmd = [sys.executable, "-m", "semgrep"] + args
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
            )
 
    # Semgrep peut renvoyer différents codes :
    # 0 = succès sans findings
    # 1 = succès avec findings
    # 2 = avertissement (dépréciation python -m semgrep) mais peut quand même avoir des résultats
    # On accepte 0, 1 et 2 comme valides
    if result.returncode not in (0, 1, 2):
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Semgrep failed",
                "return_code": result.returncode,
                "stderr_tail": (result.stderr or "")[-2000:],
            },
        )

    # Le binaire semgrep retourne le JSON dans stdout (même s'il y a des warnings dans stderr)
    stdout_text = result.stdout or ""
    
    # Si stdout est vide, c'est qu'il n'y a pas de résultats (ou erreur)
    if not stdout_text.strip():
        print(f"[DEBUG Semgrep] Stdout vide. Return code: {result.returncode}")
        return {"results": [], "errors": []}

    try:
        # Le JSON peut être sur plusieurs lignes, cherche la ligne qui commence par {
        lines = stdout_text.split('\n')
        json_start_idx = None
        for i, line in enumerate(lines):
            if line.strip().startswith('{'):
                json_start_idx = i
                break
        
        if json_start_idx is not None:
            # Extrait le JSON depuis la ligne qui commence par {
            json_text = '\n'.join(lines[json_start_idx:])
            data = json.loads(json_text)
        else:
            # Essaie de parser tout stdout
            data = json.loads(stdout_text)
        
        # S'assure que results existe
        if "results" not in data:
            data["results"] = []
        
        print(f"[DEBUG Semgrep] JSON parsé avec succès. Results count: {len(data.get('results', []))}")
        return data
    except json.JSONDecodeError as e:
        # Si le parsing échoue, retourne un JSON vide au lieu de lever une exception
        print(f"[DEBUG Semgrep] Erreur parsing JSON: {e}")
        print(f"[DEBUG Semgrep] Stdout: {stdout_text[:500]}")
        print(f"[DEBUG Semgrep] Stderr: {stderr_text[:500]}")
        return {"results": [], "errors": [{"message": f"JSON parsing failed: {str(e)}"}]}
    except Exception as e:
        # Autre erreur inattendue
        print(f"[DEBUG Semgrep] Exception inattendue: {e}")
        return {"results": [], "errors": [{"message": str(e)}]}