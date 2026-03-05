# app/core/git_utils.py
import subprocess
from pathlib import Path
from fastapi import HTTPException
from urllib.parse import urlparse


def build_auth_repo_url(repo_url: str, github_token: str) -> str:
    # Support GitHub en HTTPS (hackathon)
    parsed = urlparse(repo_url)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        return repo_url
    # git clone https://x-access-token:TOKEN@github.com/user/repo.git
    return repo_url.replace("https://", f"https://x-access-token:{github_token}@", 1)


def validate_repo_url(repo_url: str) -> str:
    repo_url = (repo_url or "").strip()
    if not repo_url:
        raise HTTPException(status_code=400, detail="repo_url is required")

    if not (
        repo_url.startswith("http://")
        or repo_url.startswith("https://")
        or repo_url.startswith("git@")
    ):
        raise HTTPException(status_code=400, detail="Invalid repo_url format")

    return repo_url


def clone_repo(repo_url: str, repo_dir: Path, github_token: str | None = None) -> None:
    """
    Clone un repo. Si github_token est fourni et URL GitHub HTTPS -> clone authentifié (repo privé).
    IMPORTANT: ne jamais logger l'URL modifiée (elle contient le token).
    """
    url = build_auth_repo_url(repo_url, github_token) if github_token else repo_url

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(repo_dir)],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "git clone failed",
                "stderr": (e.stderr or "")[-2000:],
            },
        )


def ensure_git_repo(target_dir: Path) -> None:
    """
    Nécessaire uniquement pour TruffleHog si tu utilises l'ancienne version (mode git).
    Sur un ZIP extrait, il n'y a pas de .git -> on crée un repo temporaire.
    """
    subprocess.run(["git", "init"], cwd=target_dir, capture_output=True)
    subprocess.run(["git", "config", "user.email", "temp@example.com"], cwd=target_dir, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Temp"], cwd=target_dir, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=target_dir, capture_output=True)
    subprocess.run(["git", "commit", "-m", "temp"], cwd=target_dir, capture_output=True)