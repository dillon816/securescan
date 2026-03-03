from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

# Importation de l'instance Base depuis notre fichier de configuration
from app.database import Base 

def generate_uuid():
    """Génère un identifiant unique (UUID) sous forme de chaîne de caractères."""
    return str(uuid.uuid4())

# ==========================================
# 1. TABLE USER
# ==========================================
class User(Base):
    """
    Si le module d'authentification est activé, cette table permet de gérer les utilisateurs du système.
    """
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=generate_uuid, index=True)
    username = Column(Text, nullable=False)
    email = Column(Text, unique=True, nullable=False, index=True)
    password = Column(Text, nullable=False) # Mot de passe haché
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

    # Relation: 1 User a plusieurs Projects
    projects = relationship("Project", back_populates="owner", cascade="all, delete-orphan")


# ==========================================
# 2. TABLE PROJECT
# ==========================================
class Project(Base):
    __tablename__ = "projects"

    id = Column(String, primary_key=True, default=generate_uuid, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    
    repo_url = Column(Text, nullable=False)
    language_detected = Column(String(50))
    scan_status = Column(String(50), default="pending") 
    score_global = Column(Integer, nullable=True)
    scan_date = Column(DateTime, default=datetime.utcnow) 

    owner = relationship("User", back_populates="projects")
    jobs = relationship("ScanJob", back_populates="project", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="project", cascade="all, delete-orphan")


# ==========================================
# 3. TABLE SCANJOB
# ==========================================
class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(String, primary_key=True, default=generate_uuid, index=True)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    tool_name = Column(Text, nullable=False) 
    status = Column(Text, default="pending") 
    progress = Column(Integer, default=0) 
    result_json_path = Column(Text, nullable=True) 

    project = relationship("Project", back_populates="jobs")


# ==========================================
# 4. TABLE FINDING (Table Centrale)
# ==========================================
class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=generate_uuid, index=True)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    file_path = Column(Text, nullable=False)
    line_number = Column(Integer, nullable=True)
    severity = Column(Text, nullable=False) 
    owasp_category = Column(Text, nullable=True) 
    description = Column(Text, nullable=True)
    tool_source = Column(Text, nullable=False) 
    fix_suggestion = Column(Text, nullable=True)
    fix_status = Column(Text, default="pending") 

    project = relationship("Project", back_populates="findings")
    corrections = relationship("CorrectionSuggestion", back_populates="finding", cascade="all, delete-orphan")


# ==========================================
# 5. TABLE CORRECTIONSUGGESTION
# ==========================================
class CorrectionSuggestion(Base):
    __tablename__ = "correction_suggestions"

    id = Column(String, primary_key=True, default=generate_uuid, index=True)
    finding_id = Column(String, ForeignKey("findings.id"), nullable=False)
    before_code = Column(Text, nullable=False) 
    after_code = Column(Text, nullable=False)  
    approved = Column(Boolean, default=False)  

    finding = relationship("Finding", back_populates="corrections")