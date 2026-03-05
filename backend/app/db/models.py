# app/db/models.py

import uuid
import hashlib
from datetime import datetime

from sqlalchemy import (
    Column,
    String,
    Text,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    Float,
    Index,
)
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.mysql import JSON as MySQLJSON
from pydantic import BaseModel
from typing import Optional
from app.db.database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


def make_issue_key(
    tool: str,
    rule_id: Optional[str],
    file_path: Optional[str],
    line: Optional[int],
    message: Optional[str],
) -> str:
    """
    Clé unique par scan pour dédoublonner : hash(tool+rule_id+file+line+message)
    """
    base = f"{tool}|{rule_id or ''}|{file_path or ''}|{line or ''}|{message or ''}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


# ==========================================
# 1) TABLE SCANS
# ==========================================
class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    source_type = Column(Enum("zip", "git"), nullable=False)       # zip | git
    source_ref = Column(Text, nullable=False)                      # url git | nom zip/hash
    commit_sha = Column(Text, nullable=True)

    status = Column(Enum("pending", "running", "done", "failed"), default="pending", nullable=False)

    semgrep_version = Column(Text, nullable=True)

    # MySQL: JSON (équivalent jsonb Postgres)
    summary_json = Column(MySQLJSON, nullable=True)

    error = Column(Text, nullable=True)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


# ==========================================
# 2) TABLE FINDINGS
# ==========================================
class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)

    tool = Column(Enum("semgrep", "bandit", "trufflehog"), nullable=False)

    # unique par scan: sha256 => 64 chars hex => VARCHAR(64) pour index MySQL
    issue_key = Column(String(64), nullable=False)

    rule_id = Column(Text, nullable=True)
    title = Column(Text, nullable=False)

    severity = Column(Enum("Critical", "High", "Medium", "Low", "Info"), nullable=False)

    owasp_id = Column(Text, nullable=True)
    cwe = Column(Text, nullable=True)

    file_path = Column(Text, nullable=False)

    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)

    code_snippet = Column(Text, nullable=True)
    message = Column(Text, nullable=True)

    metadata_json = Column(MySQLJSON, nullable=True)

    status = Column(Enum("open", "fixed", "ignored"), default="open", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("Scan", back_populates="findings")


# Index utile: unique par scan (scan_id + issue_key)
Index("idx_findings_scan_issuekey", Finding.scan_id, Finding.issue_key)


# ==========================================
# 3) TABLE FIX_SUGGESTIONS
# ==========================================
class FixSuggestion(Base):
    __tablename__ = "fix_suggestions"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=False, index=True)

    provider = Column(Text, nullable=False)
    prompt_version = Column(Text, nullable=True)
    confidence = Column(Float, nullable=True)

    patch_diff = Column(Text, nullable=False)
    explanation = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


# ==========================================
# 4) TABLE FIX_RUNS
# ==========================================
class FixRun(Base):
    __tablename__ = "fix_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)

    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=False, index=True)
    suggestion_id = Column(String(36), ForeignKey("fix_suggestions.id"), nullable=True)

    status = Column(Enum("pending", "applied", "failed"), default="pending", nullable=False)
    applied_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)

    output_type = Column(Enum("zip", "pr", "commit"), nullable=True)
    output_ref = Column(Text, nullable=True)

    patched_files_json = Column(MySQLJSON, nullable=True)
    patch_diff = Column(Text, nullable=True)
    