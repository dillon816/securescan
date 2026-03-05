from dotenv import load_dotenv
load_dotenv()
from fastapi import FastAPI
from app.core.cors import setup_cors
from app.api.routes import router

from app.db.database import engine
from app.db.models import Base

app = FastAPI(title="SecureScan API", version="0.1")


@app.on_event("startup")
def on_startup():
    # Création des tables au démarrage (hackathon mode)
    # -> évite de bloquer au moment de l'import
    Base.metadata.create_all(bind=engine)


setup_cors(app)
app.include_router(router)