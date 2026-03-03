import tempfile
from pathlib import Path

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse

from app.models.schemas import GitScanRequest
from app.core.zip_utils import extract_zip
from app.core.git_utils import validate_repo_url, clone_repo, ensure_git_repo

from app.services.bandit_service import run_bandit
from app.services.semgrep_service import run_semgrep
from app.services.trufflehog_service import run_trufflehog

from app.security.normalizer import normalize_results

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok"}


# =========================
# ZIP ENDPOINTS
# =========================

@router.post("/scan/semgrep")
async def scan_semgrep(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Upload a .zip file")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "project.zip"
        extract_dir = tmp_path / "project"

        zip_path.write_bytes(await file.read())
        extract_zip(zip_path, extract_dir)

        raw = run_semgrep(str(extract_dir))
        summary = {
            "findings": len(raw.get("results", [])),
            "errors": len(raw.get("errors", [])),
            "version": raw.get("version"),
        }

        issues = normalize_results("semgrep", raw)

        return JSONResponse({"tool": "semgrep", "summary": summary, "raw": raw, "issues": issues})


@router.post("/scan/bandit")
async def scan_bandit(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Upload a .zip file")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "project.zip"
        extract_dir = tmp_path / "project"

        zip_path.write_bytes(await file.read())
        extract_zip(zip_path, extract_dir)

        raw = run_bandit(str(extract_dir))
        summary = {"issues": len(raw.get("results", []))}

        issues = normalize_results("bandit", raw)

        return JSONResponse({"tool": "bandit", "summary": summary, "raw": raw, "issues": issues})


@router.post("/scan/trufflehog")
async def scan_trufflehog(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Upload a .zip file")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "project.zip"
        extract_dir = tmp_path / "project"

        zip_path.write_bytes(await file.read())
        extract_zip(zip_path, extract_dir)

        if not (extract_dir / ".git").exists():
            ensure_git_repo(extract_dir)

        raw = run_trufflehog(str(extract_dir))
        summary = {"secrets": len(raw.get("findings", []))}

        issues = normalize_results("trufflehog", raw)

        return JSONResponse({"tool": "trufflehog", "summary": summary, "raw": raw, "issues": issues})


# =========================
# GIT ENDPOINTS
# =========================

@router.post("/scan/semgrep/git")
async def scan_semgrep_git(payload: GitScanRequest):
    repo_url = validate_repo_url(payload.repo_url)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        repo_dir = tmp_path / "repo"
        clone_repo(repo_url, repo_dir)

        raw = run_semgrep(str(repo_dir))
        summary = {
            "findings": len(raw.get("results", [])),
            "errors": len(raw.get("errors", [])),
            "version": raw.get("version"),
        }

        issues = normalize_results("semgrep", raw)

        return JSONResponse({
            "tool": "semgrep",
            "input": {"type": "git", "repo_url": repo_url},
            "summary": summary,
            "raw": raw,
            "issues": issues,
        })


@router.post("/scan/bandit/git")
async def scan_bandit_git(payload: GitScanRequest):
    repo_url = validate_repo_url(payload.repo_url)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        repo_dir = tmp_path / "repo"
        clone_repo(repo_url, repo_dir)

        raw = run_bandit(str(repo_dir))
        summary = {"issues": len(raw.get("results", []))}

        issues = normalize_results("bandit", raw)

        return JSONResponse({
            "tool": "bandit",
            "input": {"type": "git", "repo_url": repo_url},
            "summary": summary,
            "raw": raw,
            "issues": issues,
        })


@router.post("/scan/trufflehog/git")
async def scan_trufflehog_git(payload: GitScanRequest):
    repo_url = validate_repo_url(payload.repo_url)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        repo_dir = tmp_path / "repo"
        clone_repo(repo_url, repo_dir)

        raw = run_trufflehog(str(repo_dir))
        summary = {"secrets": len(raw.get("findings", []))}

        issues = normalize_results("trufflehog", raw)

        return JSONResponse({
            "tool": "trufflehog",
            "input": {"type": "git", "repo_url": repo_url},
            "summary": summary,
            "raw": raw,
            "issues": issues,
        })