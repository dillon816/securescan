import shutil
import tempfile
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.services.bandit_service import run_bandit
from app.services.semgrep_service import run_semgrep
from app.services.trufflehog_service import run_trufflehog

app = FastAPI(
    title="SecureScan API",
    version="0.1",
)

# CORS pour autoriser le frontend React (localhost:3000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    # Route simple pour vérifier que l'API répond (utile en dev et en démo)
    return {"status": "ok"}


@app.post("/scan/semgrep")
async def scan_semgrep(file: UploadFile = File(...)):
    """
    Reçoit un ZIP (projet), l'extrait dans un dossier temporaire,
    lance Semgrep et renvoie les résultats.
    """

    # On force un zip pour éviter les cas bizarres 
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Upload a .zip file")

    # TemporaryDirectory : dossier supprimé automatiquement à la fin de la requête
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        zip_path = tmp_path / "project.zip"
        extract_dir = tmp_path / "project"

        # On enregistre le zip reçu (UploadFile) sur disque
        zip_path.write_bytes(await file.read())

        # On extrait le zip dans extract_dir
        try:
            shutil.unpack_archive(str(zip_path), str(extract_dir))
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid zip file")

        # On lance Semgrep sur le dossier extrait
        raw = run_semgrep(str(extract_dir))

        # Petite synthèse pour le dashboard (plus simple que d'afficher tout le raw)
        summary = {
            "findings": len(raw.get("results", [])),
            "errors": len(raw.get("errors", [])),
            "version": raw.get("version"),
        }

        # "raw" contient tout le JSON Semgrep, "summary" sert au front
        return JSONResponse(
            {
                "tool": "semgrep",
                "summary": summary,
                "raw": raw,
            }
        )
@app.post("/scan/bandit")
async def scan_bandit(file: UploadFile = File(...)):
    """
    Reçoit un ZIP (projet), l'extrait dans un dossier temporaire,
    lance Bandit et renvoie les résultats.
    """

    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Upload a .zip file")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        zip_path = tmp_path / "project.zip"
        extract_dir = tmp_path / "project"

        zip_path.write_bytes(await file.read())

        try:
            shutil.unpack_archive(str(zip_path), str(extract_dir))
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid zip file")

        raw = run_bandit(str(extract_dir))

        # Bandit renvoie un format différent de Semgrep
        # Dans son JSON, les issues sont souvent dans "results"
        results = raw.get("results", [])

        summary = {
            "issues": len(results),
            "tool": "bandit",
        }

        return JSONResponse(
            {
                "tool": "bandit",
                "summary": summary,
                "raw": raw,
            }
        )
