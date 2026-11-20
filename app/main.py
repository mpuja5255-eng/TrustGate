"""
TRUSTGATE Main Application Entry Point
"""
import os
import json
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.config import settings
from app.database.repository import init_db, seed_case_evidence, SessionLocal
from app.api.routes import router as api_router
from app.ml.model_manager import ModelManager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Database and Evidence
    init_db()
    db = SessionLocal()
    try:
        seed_case_evidence(db)
    finally:
        db.close()
    # Check ML model status
    mgr = ModelManager.get_instance()
    print(f"TRUSTGATE initialized in {settings.mode} mode. ML Status: {mgr.get_status()['status']}")
    yield
    print("TRUSTGATE shutting down.")

app = FastAPI(
    title="TRUSTGATE Defensive Gateway",
    description="Hybrid Financial & API Security Gateway combining Deterministic Policy and Isolation Forest Anomaly Detection",
    version=settings.app_version,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")

@app.get("/", response_class=HTMLResponse)
def root():
    return """
    <!DOCTYPE html>
    <html>
        <head>
            <title>TRUSTGATE — Cyber Defense Gateway</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
            <style>
                body {
                    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    background: #F7F8F3;
                    color: #25271F;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    min-height: 100vh;
                    margin: 0;
                    padding: 24px;
                    box-sizing: border-box;
                    -webkit-font-smoothing: antialiased;
                }
                .card {
                    background: #FFFFFF;
                    border: 1px solid #E7E8DC;
                    border-radius: 14px;
                    padding: 44px;
                    max-width: 520px;
                    width: 100%;
                    box-shadow: 0 4px 16px rgba(37, 39, 31, 0.05);
                }
                h1 {
                    font-size: 1.75rem;
                    margin-top: 0;
                    margin-bottom: 8px;
                    color: #25271F;
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    font-weight: 700;
                }
                .subtitle {
                    color: #77796D;
                    font-size: 0.95rem;
                    margin-bottom: 28px;
                    line-height: 1.6;
                }
                .btn-primary {
                    display: inline-block;
                    background: #B8BC86;
                    color: #25271F;
                    text-decoration: none;
                    font-weight: 600;
                    padding: 12px 24px;
                    border-radius: 8px;
                    transition: all 0.15s ease;
                }
                .btn-primary:hover {
                    background: #a8ac74;
                    transform: translateY(-1px);
                }
                .btn-secondary {
                    display: inline-block;
                    color: #25271F;
                    text-decoration: none;
                    font-size: 0.875rem;
                    font-weight: 500;
                    margin-left: 14px;
                    padding: 11px 18px;
                    border: 1px solid #E7E8DC;
                    border-radius: 8px;
                    background: #FFFFFF;
                    transition: all 0.15s ease;
                }
                .btn-secondary:hover {
                    background: #EEF0E3;
                }
                .badge {
                    display: inline-block;
                    background: #EEF0E3;
                    color: #25271F;
                    border: 1px solid #B8BC86;
                    padding: 3px 10px;
                    border-radius: 6px;
                    font-size: 0.75rem;
                    font-family: monospace;
                    font-weight: 600;
                    margin-bottom: 18px;
                }
            </style>
        </head>
        <body>
            <div class="card">
                <span class="badge">SENTINEL-X • AUTONOMOUS GATEWAY</span>
                <h1>🛡️ TRUSTGATE</h1>
                <p class="subtitle">Autonomous defensive security gateway fusing deterministic authorization contracts with unsupervised Isolation Forest behavioral anomaly detection.</p>
                <div>
                    <a href="/dashboard" class="btn-primary">👉 Open SOC Analyst Console</a>
                    <a href="/docs" class="btn-secondary">API Docs (Swagger UI) &rarr;</a>
                </div>
            </div>
        </body>
    </html>
    """

@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard():
    dashboard_html_path = os.path.join(settings.base_dir, "dashboard", "index.html")
    if os.path.exists(dashboard_html_path):
        with open(dashboard_html_path, "r", encoding="utf-8") as f:
            return f.read()
    return """
    <html><body><h2>Dashboard interface is loading...</h2></body></html>
    """

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
