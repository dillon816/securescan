import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv

# 1. Charger les variables d'environnement depuis le fichier .env
load_dotenv()

# 2. Récupérer l'URL de connexion PostgreSQL
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

# Sécurité : Vérifier que l'URL est bien trouvée, sinon on bloque l'application
if not SQLALCHEMY_DATABASE_URL:
    raise ValueError("⚠️ ERREUR : La variable DATABASE_URL est introuvable dans le fichier .env")

# 3. Créer le moteur (engine) SQLAlchemy
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# 4. Créer une usine à sessions
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 5. Créer la classe de base
Base = declarative_base()

# 6. Fonction pour obtenir une session (Dependency Injection)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()