import shutil
from pathlib import Path
from fastapi import HTTPException

def extract_zip(zip_path: Path, extract_dir: Path) -> None:
    try:
        shutil.unpack_archive(str(zip_path), str(extract_dir))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid zip file")