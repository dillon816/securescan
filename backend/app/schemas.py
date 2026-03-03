from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

# ==========================================
# 1. SCHEMAS CORRECTIONS
# ==========================================
class CorrectionBase(BaseModel):
    before_code: str
    after_code: str
    approved: bool

class CorrectionResponse(CorrectionBase):
    id: str
    finding_id: str

    class Config:
        from_attributes = True 

# ==========================================
# 2. SCHEMAS FINDINGS 
# ==========================================
class FindingBase(BaseModel):
    file_path: str
    line_number: Optional[int] = None
    severity: str
    owasp_category: Optional[str] = None
    description: Optional[str] = None
    tool_source: str
    fix_suggestion: Optional[str] = None
    fix_status: str

class FindingResponse(FindingBase):
    id: str
    project_id: str
    corrections: List[CorrectionResponse] = []  

    class Config:
        from_attributes = True

# ==========================================
# 3. SCHEMAS SCAN JOBS 
# ==========================================
class ScanJobBase(BaseModel):
    tool_name: str
    status: str
    progress: int

class ScanJobResponse(ScanJobBase):
    id: str
    project_id: str

    class Config:
        from_attributes = True

# ==========================================
# 4. SCHEMAS PROJECTS
# ==========================================
class ProjectCreate(BaseModel):
    repo_url: str

class ProjectBase(BaseModel):
    repo_url: str
    language_detected: Optional[str] = None
    scan_status: str
    score_global: Optional[int] = None
    scan_date: datetime

class ProjectResponse(ProjectBase):
    id: str

    class Config:
        from_attributes = True

#  Dashboard
class ProjectDetailResponse(ProjectResponse):
    jobs: List[ScanJobResponse] = []
    findings: List[FindingResponse] = []