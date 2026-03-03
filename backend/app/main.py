from fastapi import FastAPI
from app.core.cors import setup_cors
from app.api.routes import router

app = FastAPI(title="SecureScan API", version="0.1")

setup_cors(app)
app.include_router(router)