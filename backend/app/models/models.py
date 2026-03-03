from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

# Importation de l'instance Base depuis notre fichier de configuration
# (Assurez-vous que le fichier app/database.py exporte bien 'Base')
from app.database import Base 

def generate_uuid():
    """Génère un identifiant unique (UUID) sous forme de chaîne de caractères."""
    return str(uuid.uuid4())

class Project(Base):
    """
    Table stockant les informations principales des projets (dépôts Git) analysés.
    """
    __tablename__ = "projects"

    # Colonnes de la table Project [cite: 303]
    id = Column(String, primary_key=True, default=generate_uuid, index=True)
    repo_url = Column(Text, nullable=False)
    language_detected = Column(String(50))
    scan_status = Column(String(50), default="pending") # Statuts : pending, running, finished, error
    score_global = Column(Integer, nullable=True)
    scan_date = Column(DateTime, default=datetime.utcnow) # Date d'exécution du scan [cite: 308]

    # Mapping relationnel : Un projet est lié à plusieurs "ScanJobs" et "Findings"
    # cascade="all, delete-orphan" permet de supprimer l'historique si le projet est supprimé
    jobs = relationship("ScanJob", back_populates="project", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="project", cascade="all, delete-orphan")


class ScanJob(Base):
    """
    Table gérant l'exécution asynchrone des différents outils de sécurité (scanners).
    """
    __tablename__ = "scan_jobs"

    # Colonnes de la table ScanJob [cite: 315]
    id = Column(String, primary_key=True, default=generate_uuid, index=True)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    tool_name = Column(String(50), nullable=False) # Exemples : Semgrep, Bandit, TruffleHog
    status = Column(String(50), default="pending") # Statuts : running, completed, error
    progress = Column(Integer, default=0) # Pourcentage de progression de 0 à 100
    result_json_path = Column(Text, nullable=True) # Chemin vers le fichier JSON brut si nécessaire

    # Mapping relationnel (Lien vers le projet parent)
    project = relationship("Project", back_populates="jobs")


class Finding(Base):
    """
    Table centrale stockant chaque vulnérabilité détectée par les outils.
    """
    __tablename__ = "findings"

    # Colonnes de la table Finding [cite: 311]
    id = Column(String, primary_key=True, default=generate_uuid, index=True)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    file_path = Column(Text, nullable=False)
    line_number = Column(Integer, nullable=True)
    severity = Column(String(50), nullable=False) # Niveaux de criticité : Critical, High, Medium, Low
    owasp_category = Column(String(10), nullable=True) # Catégories OWASP : A01, A02... A10
    description = Column(Text, nullable=True)
    tool_source = Column(String(50), nullable=False) # L'outil ayant détecté la faille (ex: Semgrep)
    fix_suggestion = Column(Text, nullable=True)
    fix_status = Column(String(50), default="pending") # Statuts de correction : pending, approved, rejected

    # Mapping relationnel
    project = relationship("Project", back_populates="findings")
    # Une vulnérabilité peut avoir des propositions de correction associées
    corrections = relationship("CorrectionSuggestion", back_populates="finding", cascade="all, delete-orphan")


class CorrectionSuggestion(Base):
    """
    Table stockant les propositions de code corrigé (Avant/Après) pour le Dashboard.
    """
    __tablename__ = "correction_suggestions"

    # Colonnes de la table CorrectionSuggestion [cite: 319]
    id = Column(String, primary_key=True, default=generate_uuid, index=True)
    finding_id = Column(String, ForeignKey("findings.id"), nullable=False)
    before_code = Column(Text, nullable=False) # Extrait du code vulnérable (Avant)
    after_code = Column(Text, nullable=False)  # Proposition du code sécurisé (Après)
    approved = Column(Boolean, default=False)  # Indique si l'utilisateur a validé la correction

    # Mapping relationnel (Lien vers la vulnérabilité parente)
    finding = relationship("Finding", back_populates="corrections")