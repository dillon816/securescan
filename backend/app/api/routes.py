"""
Routes API principales de SecureScan.

Ce fichier expose :
- des endpoints de scan (ZIP et Git) pour différents outils (Semgrep, Bandit, TruffleHog)
- des endpoints de consultation (liste des scans, détails d'un scan, stats globales)
- un système de correction via Pull Request GitHub
- un rapport HTML généré à partir des données en base (scan + findings + fix runs)
"""

import tempfile
from pathlib import Path
import json
import subprocess
from datetime import datetime
from typing import Optional
import html

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from fastapi.responses import JSONResponse, HTMLResponse, Response, Response
from sqlalchemy.orm import Session

from app.models.schemas import GitScanRequest, ApplyFixRequest, AutoFixRequest
from app.core.zip_utils import extract_zip
from app.core.git_utils import validate_repo_url, clone_repo, ensure_git_repo

from app.services.github_pr_service import (
    parse_owner_repo,
    ensure_can_push,
    create_branch_commit_push,
    open_pull_request,
)

from app.services.bandit_service import run_bandit
from app.services.semgrep_service import run_semgrep
from app.services.trufflehog_service import run_trufflehog

from app.services.fix_rules import apply_classic_fix
from app.security.normalizer import normalize_results

# Dépendances base de données (SQLAlchemy)
from app.db.database import get_db
from app.db.models import Scan, Finding, make_issue_key, FixRun, FixSuggestion

router = APIRouter()


# -------------------------------------------------------------------
# Persistence : enregistrement du scan + findings normalisés en base
# -------------------------------------------------------------------
def persist_scan(
    db: Session,
    *,
    tool: str,
    input_type: str,              # "zip" | "git"
    repo_url: Optional[str],
    status: str,                  # "completed"
    summary: dict,
    issues: list[dict],
    source_ref: str,              # zip filename/hash | git repo_url
) -> str:
    """
    Enregistre un scan et ses findings dans la base de données.

    Points importants :
    - On stocke le "résultat normalisé" (issues) pour rester cohérent entre outils.
    - On garde un résumé simple (summary_json) pour le dashboard.
    - On renvoie l'UUID du scan, qui sert ensuite à consulter /scans/{scan_id} ou /report/{scan_id}.
    """

    # Dans l'API on manipule "completed/failed", en base on a un statut plus simple "done/failed"
    scan_status = "done" if status == "completed" else "failed"
    source_type = "git" if input_type == "git" else "zip"

    # Création de l'entrée Scan
    scan = Scan(
        source_type=source_type,
        source_ref=source_ref,
        commit_sha=None,
        status=scan_status,
        semgrep_version=summary.get("version") if tool == "semgrep" else None,
        summary_json=summary,
        error=None,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Conversion des sévérités normalisées (critical/high/medium/low/info) vers le format front
    sev_map = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }

    # Création des findings associés à ce scan
    for it in issues:
        # On utilise un "issue_key" stable pour éviter les doublons/logiques incohérentes
        msg = it.get("title") or it.get("message") or ""
        issue_key = make_issue_key(
            it.get("tool") or tool,
            it.get("rule_id"),
            it.get("file"),
            it.get("line"),
            msg,
        )

        db.add(
            Finding(
                scan_id=scan.id,
                tool=(it.get("tool") or tool),
                issue_key=issue_key,
                rule_id=it.get("rule_id"),
                title=it.get("title") or "Finding",
                severity=sev_map.get((it.get("severity") or "info").lower(), "Info"),
                owasp_id=it.get("owasp_id"),
                cwe=it.get("cwe"),
                file_path=it.get("file") or "",
                line_start=it.get("line"),
                line_end=it.get("line"),
                code_snippet=it.get("snippet"),
                message=it.get("owasp_title") or it.get("title"),
                metadata_json=it,
                status="open",
            )
        )

    db.commit()
    return scan.id


@router.get("/health")
def health():
    """Endpoint simple pour vérifier que l'API répond."""
    return {"status": "ok"}


# ============================================================
# ZIP ENDPOINTS : scan d'un projet uploadé sous forme de .zip
# ============================================================
@router.post("/scan/semgrep")
async def scan_semgrep(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Lance Semgrep sur un ZIP uploadé.
    - Extraction dans un dossier temporaire
    - Exécution de Semgrep
    - Normalisation des résultats
    - Persist en base + retour JSON complet
    """
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Upload a .zip file")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "project.zip"
        extract_dir = tmp_path / "project"

        # On écrit le ZIP sur disque, puis on l'extrait
        zip_path.write_bytes(await file.read())
        extract_zip(zip_path, extract_dir)

        raw = run_semgrep(str(extract_dir))
        summary = {
            "findings": len(raw.get("results", [])),
            "errors": len(raw.get("errors", [])),
            "version": raw.get("version"),
        }

        # Normalisation : on homogénéise le format peu importe l'outil
        issues = normalize_results("semgrep", raw)

        scan_id = persist_scan(
            db,
            tool="semgrep",
            input_type="zip",
            repo_url=None,
            status="completed",
            summary=summary,
            issues=issues,
            source_ref=file.filename,
        )

        return JSONResponse(
            {"scan_id": scan_id, "tool": "semgrep", "summary": summary, "raw": raw, "issues": issues}
        )


@router.post("/scan/bandit")
async def scan_bandit(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Lance Bandit sur un ZIP uploadé (projets Python).
    
    """
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

        scan_id = persist_scan(
            db,
            tool="bandit",
            input_type="zip",
            repo_url=None,
            status="completed",
            summary=summary,
            issues=issues,
            source_ref=file.filename,
        )

        return JSONResponse(
            {"scan_id": scan_id, "tool": "bandit", "summary": summary, "raw": raw, "issues": issues}
        )


@router.post("/scan/trufflehog")
async def scan_trufflehog(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Lance TruffleHog sur un ZIP uploadé.
    TruffleHog fonctionne mieux dans un contexte Git, donc si le ZIP n'a pas de .git,
    on initialise un repo Git local minimal.
    """
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Upload a .zip file")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "project.zip"
        extract_dir = tmp_path / "project"

        zip_path.write_bytes(await file.read())
        extract_zip(zip_path, extract_dir)

        # TruffleHog analyse l'historique / contexte, donc on s'assure d'un repo Git
        if not (extract_dir / ".git").exists():
            ensure_git_repo(extract_dir)

        raw = run_trufflehog(str(extract_dir))

        # Si ok=False : vrai échec. (Certains warnings Windows peuvent exister mais ok=True)
        if not raw.get("ok", False):
            raise HTTPException(status_code=400, detail=raw)

        findings = raw.get("findings", []) or []
        summary = {"secrets": len(findings), "status": raw.get("status")}

        issues = normalize_results("trufflehog", raw)

        scan_id = persist_scan(
            db,
            tool="trufflehog",
            input_type="zip",
            repo_url=None,
            status="completed",
            summary=summary,
            issues=issues,
            source_ref=file.filename,
        )

        return JSONResponse(
            {"scan_id": scan_id, "tool": "trufflehog", "summary": summary, "raw": raw, "issues": issues}
        )

@router.post("/scan/all")
async def scan_all_zip(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Upload a .zip file")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "project.zip"
        extract_dir = tmp_path / "project"

        zip_path.write_bytes(await file.read())
        extract_zip(zip_path, extract_dir)

        # Semgrep
        semgrep_raw = run_semgrep(str(extract_dir))
        semgrep_summary = {
            "findings": len(semgrep_raw.get("results", [])),
            "errors": len(semgrep_raw.get("errors", [])),
            "version": semgrep_raw.get("version"),
        }
        semgrep_issues = normalize_results("semgrep", semgrep_raw)
        semgrep_scan_id = persist_scan(
            db,
            tool="semgrep",
            input_type="zip",
            repo_url=None,
            status="completed",
            summary=semgrep_summary,
            issues=semgrep_issues,
            source_ref=file.filename,
        )

        # Bandit (skip si pas de .py)
        has_py = any(p.suffix == ".py" for p in extract_dir.rglob("*") if p.is_file())
        if has_py:
            bandit_raw = run_bandit(str(extract_dir))
            bandit_summary = {"issues": len(bandit_raw.get("results", []))}
            bandit_issues = normalize_results("bandit", bandit_raw)
            bandit_scan_id = persist_scan(
                db,
                tool="bandit",
                input_type="zip",
                repo_url=None,
                status="completed",
                summary=bandit_summary,
                issues=bandit_issues,
                source_ref=file.filename,
            )
        else:
            bandit_raw = {"skipped": True, "reason": "no_python_files"}
            bandit_summary = {"skipped": True}
            bandit_issues = []
            bandit_scan_id = None

        # TruffleHog (besoin d'un repo git)
        if not (extract_dir / ".git").exists():
            ensure_git_repo(extract_dir)

        truffle_raw = run_trufflehog(str(extract_dir))
        if not truffle_raw.get("ok", False):
            raise HTTPException(status_code=400, detail=truffle_raw)

        truffle_findings = truffle_raw.get("findings", []) or []
        truffle_summary = {"secrets": len(truffle_findings), "status": truffle_raw.get("status")}
        truffle_issues = normalize_results("trufflehog", truffle_raw)
        truffle_scan_id = persist_scan(
            db,
            tool="trufflehog",
            input_type="zip",
            repo_url=None,
            status="completed",
            summary=truffle_summary,
            issues=truffle_issues,
            source_ref=file.filename,
        )

        return JSONResponse({
            "ok": True,
            "input": {"type": "zip", "filename": file.filename},
            "scan_ids": {
                "semgrep": semgrep_scan_id,
                "bandit": bandit_scan_id,
                "trufflehog": truffle_scan_id,
            },
            "results": {
                "semgrep": {"summary": semgrep_summary, "issues": semgrep_issues},
                "bandit": {"summary": bandit_summary, "issues": bandit_issues, "raw": bandit_raw},
                "trufflehog": {"summary": truffle_summary, "issues": truffle_issues},
            },
        })
# ============================================================
# GIT ENDPOINTS : scan d'un repository GitHub (token optionnel)
# ============================================================
@router.post("/scan/semgrep/git")
async def scan_semgrep_git(payload: GitScanRequest, db: Session = Depends(get_db)):
    """
    Scan Semgrep directement sur un repo Git.
    - validate_repo_url : évite les URL non conformes
    - clone_repo : clone avec token si fourni (repo privé / quotas)
    """
    repo_url = validate_repo_url(payload.repo_url)
    token = payload.github_token

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        repo_dir = tmp_path / "repo"

        clone_repo(repo_url, repo_dir, github_token=token)

        raw = run_semgrep(str(repo_dir))
        summary = {
            "findings": len(raw.get("results", [])),
            "errors": len(raw.get("errors", [])),
            "version": raw.get("version"),
        }

        issues = normalize_results("semgrep", raw)

        scan_id = persist_scan(
            db,
            tool="semgrep",
            input_type="git",
            repo_url=repo_url,
            status="completed",
            summary=summary,
            issues=issues,
            source_ref=repo_url,
        )

        return JSONResponse(
            {
                "scan_id": scan_id,
                "tool": "semgrep",
                "input": {"type": "git", "repo_url": repo_url},
                "summary": summary,
                "raw": raw,
                "issues": issues,
            }
        )


@router.post("/scan/bandit/git")
async def scan_bandit_git(payload: GitScanRequest, db: Session = Depends(get_db)):
    """Même logique que Semgrep Git, mais avec Bandit."""
    repo_url = validate_repo_url(payload.repo_url)
    token = payload.github_token

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        repo_dir = tmp_path / "repo"

        clone_repo(repo_url, repo_dir, github_token=token)

        raw = run_bandit(str(repo_dir))
        summary = {"issues": len(raw.get("results", []))}

        issues = normalize_results("bandit", raw)

        scan_id = persist_scan(
            db,
            tool="bandit",
            input_type="git",
            repo_url=repo_url,
            status="completed",
            summary=summary,
            issues=issues,
            source_ref=repo_url,
        )

        return JSONResponse(
            {
                "scan_id": scan_id,
                "tool": "bandit",
                "input": {"type": "git", "repo_url": repo_url},
                "summary": summary,
                "raw": raw,
                "issues": issues,
            }
        )


@router.post("/scan/trufflehog/git")
async def scan_trufflehog_git(payload: GitScanRequest, db: Session = Depends(get_db)):
    """TruffleHog sur repo Git (détection de secrets)."""
    repo_url = validate_repo_url(payload.repo_url)
    token = payload.github_token

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        repo_dir = tmp_path / "repo"

        clone_repo(repo_url, repo_dir, github_token=token)

        raw = run_trufflehog(str(repo_dir))

        if not raw.get("ok", False):
            raise HTTPException(status_code=400, detail=raw)

        findings = raw.get("findings", []) or []
        summary = {"secrets": len(findings), "status": raw.get("status")}

        issues = normalize_results("trufflehog", raw)

        scan_id = persist_scan(
            db,
            tool="trufflehog",
            input_type="git",
            repo_url=repo_url,
            status="completed",
            summary=summary,
            issues=issues,
            source_ref=repo_url,
        )

        return JSONResponse(
            {
                "scan_id": scan_id,
                "tool": "trufflehog",
                "input": {"type": "git", "repo_url": repo_url},
                "summary": summary,
                "raw": raw,
                "issues": issues,
            }
        )

@router.post("/scan/all/git")
async def scan_all_git(payload: GitScanRequest, db: Session = Depends(get_db)):
    repo_url = validate_repo_url(payload.repo_url)
    token = payload.github_token

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        repo_dir = tmp_path / "repo"
        clone_repo(repo_url, repo_dir, github_token=token)

        # Semgrep
        semgrep_raw = run_semgrep(str(repo_dir))
        semgrep_summary = {
            "findings": len(semgrep_raw.get("results", [])),
            "errors": len(semgrep_raw.get("errors", [])),
            "version": semgrep_raw.get("version"),
        }
        semgrep_issues = normalize_results("semgrep", semgrep_raw)
        semgrep_scan_id = persist_scan(
            db,
            tool="semgrep",
            input_type="git",
            repo_url=repo_url,
            status="completed",
            summary=semgrep_summary,
            issues=semgrep_issues,
            source_ref=repo_url,
        )

        # Bandit (skip si pas de .py)
        has_py = any(p.suffix == ".py" for p in repo_dir.rglob("*") if p.is_file())
        if has_py:
            bandit_raw = run_bandit(str(repo_dir))
            bandit_summary = {"issues": len(bandit_raw.get("results", []))}
            bandit_issues = normalize_results("bandit", bandit_raw)
            bandit_scan_id = persist_scan(
                db,
                tool="bandit",
                input_type="git",
                repo_url=repo_url,
                status="completed",
                summary=bandit_summary,
                issues=bandit_issues,
                source_ref=repo_url,
            )
        else:
            bandit_raw = {"skipped": True, "reason": "no_python_files"}
            bandit_summary = {"skipped": True}
            bandit_issues = []
            bandit_scan_id = None

        # TruffleHog
        truffle_raw = run_trufflehog(str(repo_dir))
        if not truffle_raw.get("ok", False):
            raise HTTPException(status_code=400, detail=truffle_raw)

        truffle_findings = truffle_raw.get("findings", []) or []
        truffle_summary = {"secrets": len(truffle_findings), "status": truffle_raw.get("status")}
        truffle_issues = normalize_results("trufflehog", truffle_raw)
        truffle_scan_id = persist_scan(
            db,
            tool="trufflehog",
            input_type="git",
            repo_url=repo_url,
            status="completed",
            summary=truffle_summary,
            issues=truffle_issues,
            source_ref=repo_url,
        )

        return JSONResponse({
            "ok": True,
            "input": {"type": "git", "repo_url": repo_url},
            "scan_ids": {
                "semgrep": semgrep_scan_id,
                "bandit": bandit_scan_id,
                "trufflehog": truffle_scan_id,
            },
            "results": {
                "semgrep": {"summary": semgrep_summary, "issues": semgrep_issues},
                "bandit": {"summary": bandit_summary, "issues": bandit_issues, "raw": bandit_raw},
                "trufflehog": {"summary": truffle_summary, "issues": truffle_issues},
            },
        })
# ============================================================
# DASHBOARD : endpoints de consultation des données persistées
# ============================================================
@router.get("/scans")
def list_scans(limit: int = 50, db: Session = Depends(get_db)):
    """
    Retourne les derniers scans .
    On limite par défaut à 50 pour éviter des réponses énormes.
    """
    scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(limit).all()
    return [
        {
            "id": s.id,
            "created_at": s.created_at.isoformat(),
            "source_type": s.source_type,
            "source_ref": s.source_ref,
            "commit_sha": s.commit_sha,
            "status": s.status,
            "semgrep_version": s.semgrep_version,
            "summary_json": s.summary_json or {},
            "error": s.error,
        }
        for s in scans
    ]


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """
    Détail complet d'un scan 
    
    """
    s = db.query(Scan).filter(Scan.id == scan_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    return {
        "id": s.id,
        "created_at": s.created_at.isoformat(),
        "source_type": s.source_type,
        "source_ref": s.source_ref,
        "commit_sha": s.commit_sha,
        "status": s.status,
        "semgrep_version": s.semgrep_version,
        "summary_json": s.summary_json or {},
        "error": s.error,
        "findings": [
            {
                "id": f.id,
                "scan_id": f.scan_id,
                "tool": f.tool,
                "issue_key": f.issue_key,
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "owasp_id": f.owasp_id,
                "cwe": f.cwe,
                "file_path": f.file_path,
                "line_start": f.line_start,
                "line_end": f.line_end,
                "code_snippet": f.code_snippet,
                "message": f.message,
                "metadata_json": f.metadata_json or {},
                "status": f.status,
                "created_at": f.created_at.isoformat(),
            }
            for f in findings
        ],
    }


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """
    Stats globales (tous scans confondus).
    Utile pour un écran "Overview" : volume total de scans / findings, distribution sévérité, etc.
    """
    scans = db.query(Scan).all()
    findings = db.query(Finding).all()

    total_scans = len(scans)
    total_findings = len(findings)

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        if f.severity in sev_counts:
            sev_counts[f.severity] += 1

    owasp_counts = {}
    for f in findings:
        if f.owasp_id:
            owasp_counts[f.owasp_id] = owasp_counts.get(f.owasp_id, 0) + 1

    top_owasp = None
    if owasp_counts:
        top_owasp = max(owasp_counts, key=owasp_counts.get)

    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "severity": sev_counts,
        "top_owasp": top_owasp,
        "owasp_distribution": owasp_counts,
    }


# ============================================================
# PR : application d'un patch via Pull Request GitHub
# ============================================================
@router.post("/fix/apply/github")
def apply_fix_github(payload: ApplyFixRequest):
    """
    Applique un patch Git sur un repository.

Étapes :
- création d'une branche
- application du patch
- création d'une Pull Request GitHub

    """
    owner, repo = parse_owner_repo(payload.repo_url)

    # Vérification des droits d'écriture sur le repo
    ensure_can_push(owner, repo, payload.github_token)

    # Branche unique pour éviter les collisions
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    branch = f"securescan-fix-{owner}-{repo}-{timestamp}"
    branch = branch.replace("_", "-").lower()
    branch = branch[:60]

    branch_name, head_sha = create_branch_commit_push(
        repo_url=payload.repo_url,
        token=payload.github_token,
        base_branch=payload.base_branch or "main",
        branch_name=branch,
        commit_msg=payload.title or "SecureScan: apply fix",
        patch_diff=payload.patch_diff,
    )

    pr = open_pull_request(
        owner=owner,
        repo=repo,
        token=payload.github_token,
        title=payload.title or "SecureScan: apply fix",
        body=payload.body or "This PR was generated by SecureScan.",
        head=branch_name,
        base=payload.base_branch or "main",
    )

    return {
        "ok": True,
        "repo": f"{owner}/{repo}",
        "branch": branch_name,
        "head_sha": head_sha,
        "pr": {
            "number": pr.get("number"),
            "title": pr.get("title"),
            "url": pr.get("html_url"),
            "state": pr.get("state"),
        },
    }


@router.post("/fix/auto/github")
def auto_fix_github(payload: AutoFixRequest, db: Session = Depends(get_db)):
    """
    Applique automatiquement un correctif sur une vulnérabilité et crée une Pull Request GitHub.
    """
    finding = db.query(Finding).filter(Finding.id == payload.finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    repo_url = validate_repo_url(payload.repo_url)

    # On refuse d'auto-fixer certains dossiers (assets build, vendor, node_modules…)
    # Objectif : éviter de modifier du code généré / dépendances.
    file_path = (finding.file_path or "").replace("\\", "/")
    blocked_parts = [
        "node_modules/",
        "vendor/",
        "dist/",
        "build/",
        "public/assets/vendor/",
        "public/assets/",
        "assets/vendor/",
    ]
    if any(part in file_path for part in blocked_parts):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Auto fix disabled for vendor/generated files",
                "file_path": file_path,
            },
        )

    # On crée un FixRun dès le début pour garder une trace, même en cas d'échec
    fix_run = FixRun(
        scan_id=finding.scan_id,
        finding_id=finding.id,
        status="pending",
    )
    db.add(fix_run)
    db.commit()
    db.refresh(fix_run)

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo_dir = tmp_path / "repo"

            clone_repo(repo_url, repo_dir, github_token=payload.github_token)

            # Application des règles de correction (template-based)
            result = apply_classic_fix(
                repo_dir,
                {
                    "tool": finding.tool,
                    "rule_id": finding.rule_id,
                    "title": finding.title,
                    "file_path": file_path,
                    "line": finding.line_start,
                },
            )

            # Si aucune règle ne s'applique, on trace et on renvoie une erreur claire
            if not result.get("ok"):
                fix_run.status = "failed"
                fix_run.error = f"No classic fix applied ({result.get('rule')})"
                db.commit()

                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "No classic fix applied",
                        "rule": result.get("rule"),
                        "file_path": file_path,
                    },
                )

            # Génération du patch Git à partir du diff local
            # On essaie d'abord de limiter au fichier concerné.
            patch = subprocess.run(
                ["git", "diff", "--no-color", "--", file_path],
                cwd=repo_dir,
                capture_output=True,
                text=True,
            ).stdout or ""

            # Fallback : si d'autres fichiers ont été modifiés (ex: .gitignore)
            if not patch.strip():
                patch = subprocess.run(
                    ["git", "diff", "--no-color"],
                    cwd=repo_dir,
                    capture_output=True,
                    text=True,
                ).stdout or ""

            if not patch.strip():
                fix_run.status = "failed"
                fix_run.error = "No diff produced (nothing to commit)"
                db.commit()
                raise HTTPException(status_code=400, detail="No diff produced (nothing to commit)")

            # Trace de la proposition (même si c'est un fix "classic")
            suggestion = FixSuggestion(
                finding_id=finding.id,
                provider="classic_rules",
                prompt_version="v1",
                confidence=0.7,
                patch_diff=patch,
                explanation=f"Auto fix generated using rule: {result.get('rule')}",
            )
            db.add(suggestion)
            db.commit()
            db.refresh(suggestion)

            # Réutilisation du flux PR déjà existant (apply_fix_github)
            apply_payload = ApplyFixRequest(
                repo_url=payload.repo_url,
                github_token=payload.github_token,
                base_branch=payload.base_branch,
                patch_diff=patch,
                title=payload.title,
                body=payload.body,
            )

            pr_result = apply_fix_github(apply_payload)

            # Mise à jour du FixRun + du statut du finding
            fix_run.status = "applied"
            fix_run.applied_at = datetime.utcnow()
            fix_run.suggestion_id = suggestion.id

            fix_run.output_type = "pr"
            fix_run.output_ref = (pr_result.get("pr") or {}).get("url")

            fix_run.patched_files_json = result.get("modified_files") or result.get("changed_files") or []
            fix_run.patch_diff = patch

            finding.status = "fixed"

            db.commit()
            return pr_result

    except HTTPException:
        # Cas d'erreur attendu : on laisse FastAPI gérer la réponse
        raise
    except Exception as e:
        # Cas inattendu : on log dans FixRun pour avoir une trace exploitable
        fix_run.status = "failed"
        fix_run.error = str(e)[:2000]
        db.commit()
        raise


# ============================================================
# REPORT : génération d'un rapport HTML depuis la base
# ============================================================
@router.get("/report/{scan_id}", response_class=HTMLResponse)
def report_scan(scan_id: str, db: Session = Depends(get_db)):
    """
    Génère un rapport HTML lisible à partir des données en base.

    Ce rapport est volontairement "server-side" :
    - pas besoin du front pour avoir un rapport exportable / partageable
    - permet  de vérifier rapidement un scan, ses findings et les fix runs associés
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    fix_runs = db.query(FixRun).filter(FixRun.scan_id == scan_id).all()

    # On précharge les suggestions liées aux fix runs (si elles existent)
    suggestion_ids = [fr.suggestion_id for fr in fix_runs if fr.suggestion_id]
    suggestions_by_id = {}
    if suggestion_ids:
        rows = db.query(FixSuggestion).filter(FixSuggestion.id.in_(suggestion_ids)).all()
        suggestions_by_id = {s.id: s for s in rows}

    # Calcul des stats de sévérité et de répartition OWASP
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        if f.severity in sev_counts:
            sev_counts[f.severity] += 1

    owasp_counts = {}
    for f in findings:
        if f.owasp_id:
            owasp_counts[f.owasp_id] = owasp_counts.get(f.owasp_id, 0) + 1

    # Escape HTML : évite les soucis d'affichage et les injections dans le rapport
    def esc(x) -> str:
        return html.escape(str(x)) if x is not None else ""

    created_at = scan.created_at.isoformat() if scan.created_at else ""

    # Construction du HTML (template léger inline)
    html_out = f"""
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>SecureScan Report - {esc(scan_id)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; background:#0b0f19; color:#e5e7eb; margin:0; padding:24px; }}
    .container {{ max-width: 1100px; margin: 0 auto; }}
    .card {{ background:#111827; border:1px solid #1f2937; border-radius:12px; padding:16px; margin-bottom:16px; }}
    h1,h2 {{ margin:0 0 12px 0; }}
    .muted {{ color:#9ca3af; font-size:14px; }}
    table {{ width:100%; border-collapse: collapse; margin-top:12px; }}
    th, td {{ border-bottom:1px solid #1f2937; padding:10px; text-align:left; vertical-align:top; }}
    th {{ color:#cbd5e1; font-weight:600; }}
    .pill {{ display:inline-block; padding:2px 10px; border-radius:999px; font-size:12px; border:1px solid #374151; }}
    .sev-Critical {{ background: rgba(239,68,68,.15); border-color: rgba(239,68,68,.35); }}
    .sev-High {{ background: rgba(249,115,22,.15); border-color: rgba(249,115,22,.35); }}
    .sev-Medium {{ background: rgba(234,179,8,.15); border-color: rgba(234,179,8,.35); }}
    .sev-Low {{ background: rgba(34,197,94,.15); border-color: rgba(34,197,94,.35); }}
    .sev-Info {{ background: rgba(59,130,246,.15); border-color: rgba(59,130,246,.35); }}
    a {{ color:#60a5fa; text-decoration:none; }}
    a:hover {{ text-decoration:underline; }}
    code {{ background:#0b1220; border:1px solid #1f2937; padding:2px 6px; border-radius:6px; }}
    .grid {{ display:grid; grid-template-columns: 1fr 1fr; gap:12px; }}
    @media (max-width: 900px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <div class="container">

    <div class="card">
      <h1>SecureScan Report</h1>
      <div class="muted">
        Scan ID: <code>{esc(scan.id)}</code><br/>
        Date: <code>{esc(created_at)}</code><br/>
        Source: <code>{esc(scan.source_type)}</code> — {esc(scan.source_ref)}<br/>
        Status: <code>{esc(scan.status)}</code>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <h2>Summary</h2>
        <table>
          <tr><th>Severity</th><th>Count</th></tr>
          <tr><td>Critical</td><td>{sev_counts["Critical"]}</td></tr>
          <tr><td>High</td><td>{sev_counts["High"]}</td></tr>
          <tr><td>Medium</td><td>{sev_counts["Medium"]}</td></tr>
          <tr><td>Low</td><td>{sev_counts["Low"]}</td></tr>
          <tr><td>Info</td><td>{sev_counts["Info"]}</td></tr>
        </table>
        <div class="muted" style="margin-top:10px;">
          Total findings: <code>{len(findings)}</code>
        </div>
      </div>

      <div class="card">
        <h2>OWASP</h2>
        <table>
          <tr><th>OWASP ID</th><th>Count</th></tr>
    """

    if owasp_counts:
        for k in sorted(owasp_counts.keys()):
            html_out += f"<tr><td>{esc(k)}</td><td>{owasp_counts[k]}</td></tr>"
    else:
        html_out += "<tr><td colspan='2' class='muted'>Aucune correspondance OWASP</td></tr>"

    html_out += """
        </table>
      </div>
    </div>

    <div class="card">
      <h2>Findings</h2>
      <table>
        <tr>
          <th>Tool</th>
          <th>Severity</th>
          <th>Title</th>
          <th>File</th>
          <th>Line</th>
          <th>Rule</th>
          <th>OWASP</th>
          <th>Status</th>
        </tr>
    """

    for f in findings:
        sev = f.severity or "Info"
        pill_cls = f"pill sev-{sev}"
        html_out += f"""
        <tr>
          <td>{esc(f.tool)}</td>
          <td><span class="{pill_cls}">{esc(sev)}</span></td>
          <td>{esc(f.title)}</td>
          <td><code>{esc(f.file_path)}</code></td>
          <td>{esc(f.line_start)}</td>
          <td>{esc(f.rule_id)}</td>
          <td>{esc(f.owasp_id)}</td>
          <td>{esc(f.status)}</td>
        </tr>
        """

    if not findings:
        html_out += "<tr><td colspan='8' class='muted'>Aucun finding</td></tr>"

    html_out += """
      </table>
    </div>

    <div class="card">
      <h2>Fix Runs</h2>
      <table>
        <tr>
          <th>Status</th>
          <th>Finding</th>
          <th>Output</th>
          <th>Applied at</th>
          <th>Provider</th>
          <th>Details</th>
        </tr>
    """

    for fr in fix_runs:
        applied_at = fr.applied_at.isoformat() if fr.applied_at else ""

        # Lien cliquable si on a une URL (ex: PR GitHub)
        out = ""
        if fr.output_type and fr.output_ref:
            if "http" in (fr.output_ref or ""):
                out = f'<a href="{esc(fr.output_ref)}" target="_blank">{esc(fr.output_type)}</a>'
            else:
                out = f"{esc(fr.output_type)}: {esc(fr.output_ref)}"

        provider = ""
        details = ""

        # Si on a une suggestion, on affiche provider + explication (utile pour comprendre la règle appliquée)
        if fr.suggestion_id and fr.suggestion_id in suggestions_by_id:
            s = suggestions_by_id[fr.suggestion_id]
            provider = s.provider or ""
            details = s.explanation or ""
        elif fr.error:
            # Sinon, en cas d'échec, on affiche l'erreur enregistrée
            details = fr.error

        html_out += f"""
        <tr>
          <td>{esc(fr.status)}</td>
          <td><code>{esc(fr.finding_id)}</code></td>
          <td>{out}</td>
          <td>{esc(applied_at)}</td>
          <td>{esc(provider)}</td>
          <td class="muted">{esc(details)}</td>
        </tr>
        """

    if not fix_runs:
        html_out += "<tr><td colspan='6' class='muted'>Aucun FixRun pour ce scan</td></tr>"

    html_out += """
      </table>
      <div class="muted" style="margin-top:10px;">
        Ce rapport est généré uniquement depuis la base de données : scans, findings, fix runs, fix suggestions.
      </div>
    </div>

  </div>
</body>
</html>
"""

    return HTMLResponse(content=html_out)


@router.get("/report/{scan_id}/pdf")
def report_scan_pdf(scan_id: str, db: Session = Depends(get_db)):
    """
    Génère un rapport PDF à partir des données en base.
    """
    try:
        from weasyprint import HTML
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="WeasyPrint n'est pas installé. Installez-le avec: pip install weasyprint"
        )
    
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    fix_runs = db.query(FixRun).filter(FixRun.scan_id == scan_id).all()

    suggestion_ids = [fr.suggestion_id for fr in fix_runs if fr.suggestion_id]
    suggestions_by_id = {}
    if suggestion_ids:
        rows = db.query(FixSuggestion).filter(FixSuggestion.id.in_(suggestion_ids)).all()
        suggestions_by_id = {s.id: s for s in rows}

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        if f.severity in sev_counts:
            sev_counts[f.severity] += 1

    owasp_counts = {}
    for f in findings:
        if f.owasp_id:
            owasp_counts[f.owasp_id] = owasp_counts.get(f.owasp_id, 0) + 1

    def esc(x) -> str:
        return html.escape(str(x)) if x is not None else ""

    created_at = scan.created_at.isoformat() if scan.created_at else ""

    # Génère le même HTML que l'endpoint HTML (version simplifiée pour PDF)
    html_out = f"""
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8"/>
  <title>SecureScan Report - {esc(scan_id)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 20px; color: #333; }}
    h1 {{ color: #b54a72; border-bottom: 2px solid #b54a72; padding-bottom: 10px; }}
    h2 {{ color: #555; margin-top: 30px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 10px; }}
    th, td {{ border: 1px solid #ddd; padding: 6px; text-align: left; }}
    th {{ background-color: #f5f5f5; font-weight: bold; }}
    .muted {{ color: #666; font-size: 0.9em; }}
    .severity-critical {{ color: #d32f2f; font-weight: bold; }}
    .severity-high {{ color: #f57c00; font-weight: bold; }}
    .severity-medium {{ color: #fbc02d; }}
    .severity-low {{ color: #388e3c; }}
  </style>
</head>
<body>
  <h1>🛡️ SecureScan - Rapport d'analyse</h1>
  
  <div>
    <h2>Informations du scan</h2>
    <table>
      <tr><th>Scan ID</th><td>{esc(scan_id)}</td></tr>
      <tr><th>Date</th><td>{esc(created_at)}</td></tr>
      <tr><th>Type de source</th><td>{esc(scan.source_type)}</td></tr>
      <tr><th>Référence</th><td>{esc(scan.source_ref)}</td></tr>
      <tr><th>Statut</th><td>{esc(scan.status)}</td></tr>
    </table>

    <h2>Statistiques</h2>
    <table>
      <tr><th>Sévérité</th><th>Nombre</th></tr>
      <tr><td class="severity-critical">Critical</td><td>{sev_counts['Critical']}</td></tr>
      <tr><td class="severity-high">High</td><td>{sev_counts['High']}</td></tr>
      <tr><td class="severity-medium">Medium</td><td>{sev_counts['Medium']}</td></tr>
      <tr><td class="severity-low">Low</td><td>{sev_counts['Low']}</td></tr>
      <tr><td>Info</td><td>{sev_counts['Info']}</td></tr>
    </table>

    <h2>Vulnérabilités détectées ({len(findings)})</h2>
    <table>
      <tr>
        <th>Outil</th>
        <th>Règle</th>
        <th>Sévérité</th>
        <th>OWASP</th>
        <th>Fichier</th>
        <th>Ligne</th>
        <th>Description</th>
      </tr>
"""
    
    for f in findings:
        html_out += f"""
      <tr>
        <td>{esc(f.tool)}</td>
        <td>{esc(f.rule_id)}</td>
        <td class="severity-{esc(f.severity).lower()}">{esc(f.severity)}</td>
        <td>{esc(f.owasp_id or '—')}</td>
        <td>{esc(f.file_path)}</td>
        <td>{esc(f.line_start)}</td>
        <td>{esc((f.message or f.title)[:80])}</td>
      </tr>
"""

    html_out += """
    </table>

    <h2>Corrections appliquées</h2>
    <table>
      <tr>
        <th>Finding ID</th>
        <th>Statut</th>
        <th>Date</th>
        <th>Erreur</th>
      </tr>
"""
    
    for fr in fix_runs:
        html_out += f"""
      <tr>
        <td>{esc(fr.finding_id)}</td>
        <td>{esc(fr.status)}</td>
        <td>{esc(fr.created_at.isoformat() if fr.created_at else '')}</td>
        <td>{esc(fr.error or '')}</td>
      </tr>
"""

    html_out += """
    </table>
  </div>
</body>
</html>
"""
    
    # Convertit le HTML en PDF
    pdf_bytes = HTML(string=html_out).write_pdf()
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="securescan-report-{scan_id}.pdf"'
        }
    )