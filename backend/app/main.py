from fastapi import FastAPI
from app.core.cors import setup_cors
from app.api.routes import router

from app.database import engine, Base

from app.models.models import Project, ScanJob, Finding, CorrectionSuggestion, User

app = FastAPI(title="SecureScan API", version="0.1")

Base.metadata.create_all(bind=engine)

setup_cors(app)
app.include_router(router)