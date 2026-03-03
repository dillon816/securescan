from pydantic import BaseModel

class GitScanRequest(BaseModel):
    repo_url: str