import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import requests
from fastapi import HTTPException


def _run(cmd: list[str], cwd: Path | None = None) -> str:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True)
    if p.returncode != 0:
        raise HTTPException(
            status_code=400,
            detail={"error": "command failed", "cmd": cmd, "stderr": (p.stderr or "")[-2000:]},
        )
    return (p.stdout or "").strip()


def parse_owner_repo(repo_url: str) -> tuple[str, str]:
    # Supporte https://github.com/owner/repo (avec ou sans .git)
    repo_url = repo_url.strip()
    if repo_url.endswith(".git"):
        repo_url = repo_url[:-4]
    u = urlparse(repo_url)
    if u.netloc.lower() != "github.com":
        raise HTTPException(status_code=400, detail="Only github.com repos are supported for PR flow")
    parts = u.path.strip("/").split("/")
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail="Invalid GitHub repo URL")
    return parts[0], parts[1]


def github_get_repo_permissions(owner: str, repo: str, token: str) -> dict:
    r = requests.get(
        f"https://api.github.com/repos/{owner}/{repo}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        timeout=15,
    )
    if r.status_code != 200:
        raise HTTPException(
            status_code=400,
            detail={"error": "GitHub repo lookup failed", "status": r.status_code, "body": r.text[:1000]},
        )
    return r.json().get("permissions", {}) or {}


def ensure_can_push(owner: str, repo: str, token: str) -> None:
    perms = github_get_repo_permissions(owner, repo, token)
    if not perms.get("push", False):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "User token has no push permission on this repo",
                "permissions": perms,
            },
        )


def build_auth_repo_url(repo_url: str, token: str) -> str:
    # Format GitHub recommandé: https://x-access-token:TOKEN@github.com/owner/repo.git
    base = repo_url if repo_url.endswith(".git") else repo_url + ".git"
    return base.replace("https://", f"https://x-access-token:{token}@")


def apply_unified_diff(repo_dir: Path, patch_diff: str) -> None:
    """
    Applique un diff "unified" via `git apply`.
    Important : on évite de créer un fichier qui pourrait finir dans le commit.
    """
    try:
        p = subprocess.run(
            ["git", "apply", "--reject", "--whitespace=nowarn", "--"],
            cwd=str(repo_dir),
            input=patch_diff,
            text=True,
            capture_output=True,
        )
        if p.returncode != 0:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Patch could not be applied",
                    "stderr": (p.stderr or "")[-2000:],
                },
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail={"error": "Patch apply crashed", "detail": str(e)})


def _push_with_fallback_branch(repo_dir: Path, branch_name: str) -> str:
    """
    Pousse la branche.
    Si elle existe déjà sur le remote (fetch first), on bascule sur un nom unique.
    """
    p = subprocess.run(
        ["git", "push", "-u", "origin", branch_name],
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
    )
    if p.returncode == 0:
        return branch_name

    stderr = (p.stderr or "")

    # Cas classique: branche distante existe déjà -> "fetch first"
    if "fetch first" in stderr.lower() or "[rejected]" in stderr.lower():
        suffix = _run(["git", "rev-parse", "--short", "HEAD"], cwd=repo_dir)
        alt_branch = f"{branch_name}-{suffix}".lower()[:60]

        p2 = subprocess.run(
            ["git", "push", "-u", "origin", alt_branch],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
        )
        if p2.returncode == 0:
            return alt_branch

        raise HTTPException(
            status_code=400,
            detail={"error": "git push failed", "stderr": (p2.stderr or "")[-2000:]},
        )

    raise HTTPException(
        status_code=400,
        detail={"error": "git push failed", "stderr": stderr[-2000:]},
    )


def create_branch_commit_push(
    repo_url: str,
    token: str,
    base_branch: str,
    branch_name: str,
    commit_msg: str,
    patch_diff: str
) -> tuple[str, str]:
    """
    Clone -> checkout base -> create branch -> apply patch -> commit -> push.
    Retourne (branch_name_effectif, head_sha)
    """
    auth_url = build_auth_repo_url(repo_url, token)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        repo_dir = tmp_path / "repo"

        _run(["git", "clone", "--depth", "1", "--branch", base_branch, auth_url, str(repo_dir)])
        _run(["git", "checkout", "-b", branch_name], cwd=repo_dir)

        apply_unified_diff(repo_dir, patch_diff)

        # Si aucun changement réel, on stop tout de suite
        status = _run(["git", "status", "--porcelain"], cwd=repo_dir)
        if not status.strip():
            raise HTTPException(status_code=400, detail="Patch applied but produced no changes")

        # On commit uniquement les fichiers modifiés par le patch
        _run(["git", "add", "-A"], cwd=repo_dir)
        _run(["git", "commit", "-m", commit_msg], cwd=repo_dir)

        head_sha = _run(["git", "rev-parse", "HEAD"], cwd=repo_dir)

        # Push : si branche existe déjà, on bascule sur un nom unique
        effective_branch = _push_with_fallback_branch(repo_dir, branch_name)

        return effective_branch, head_sha


def open_pull_request(owner: str, repo: str, token: str, title: str, body: str, head: str, base: str) -> dict:
    r = requests.post(
        f"https://api.github.com/repos/{owner}/{repo}/pulls",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        json={
            "title": title,
            "body": body,
            "head": head,
            "base": base,
        },
        timeout=20,
    )
    if r.status_code not in (201,):
        raise HTTPException(status_code=400, detail={"error": "GitHub PR creation failed", "status": r.status_code, "body": r.text[:1500]})
    return r.json()