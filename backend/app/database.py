import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from dotenv import load_dotenv

# 1. Charger les variables d'environnement depuis le fichier .env
load_dotenv()

# 2. Récupérer l'URL de connexion PostgreSQL
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

# Sécurité : Vérifier que l'URL est bien trouvée, sinon on bloque l'application
if not SQLALCHEMY_DATABASE_URL:
    raise ValueError(" ERREUR : La variable DATABASE_URL est introuvable dans le fichier .env")

# 3. Créer le moteur (engine) SQLAlchemy pour se connecter à PostgreSQL
# Pas besoin de check_same_thread=False car c'est spécifique à SQLite. PostgreSQL gère ça très bien.
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# 4. Créer une usine à sessions pour interagir avec la base de données
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 5. Créer la classe de base dont tous nos modèles (dans models.py) vont hériter
Base = declarative_base()

# 6. Fonction pour obtenir une session de base de données (À utiliser comme Dépendance dans FastAPI)
def get_db():
    """
    Crée une session de base de données par requête et la ferme automatiquement à la fin.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()