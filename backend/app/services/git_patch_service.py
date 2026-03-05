import subprocess
from pathlib import Path

def get_repo_patch(repo_dir: Path) -> str:
    # patch depuis les changements non commit
    p = subprocess.run(
        ["git", "diff"],
        cwd=repo_dir,
        capture_output=True,
        text=True,
    )
    return (p.stdout or "").strip()