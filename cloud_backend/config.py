import os
from typing import List

class CloudConfig:
    # Ingestion API Key (Must match between cloud_sync and cloud_backend)
    INGEST_API_KEY: str = os.getenv("INGEST_API_KEY", "hg_sec_token_9f82d1a4e76c")
    
    # Database connection URL (PostgreSQL or SQLite)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./hellguardian_cloud.db")
    
    # Sensor offline timeout in seconds (5 minutes default)
    OFFLINE_TIMEOUT_SECONDS: int = int(os.getenv("OFFLINE_TIMEOUT_SECONDS", "300"))
    
    # Host and port
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8090"))
    
    # CORS Origins (Allow all by default for GitHub Pages access)
    CORS_ORIGINS: List[str] = ["*"]
    
    # VirusTotal API Key for cloud enrichment (optional)
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    
    # Gemini API Key for dynamic reports (optional)
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")

config = CloudConfig()
