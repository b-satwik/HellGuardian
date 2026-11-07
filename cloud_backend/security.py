from fastapi import Header, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from cloud_backend.config import config

API_KEY_HEADER = APIKeyHeader(name="X-Ingest-Key", auto_error=False)

def verify_ingest_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    """
    Validates X-Ingest-Key header against configured cloud INGEST_API_KEY.
    Accepts configured cloud key or the standard VM publisher secret.
    """
    valid_keys = {
        config.INGEST_API_KEY,
        "hg_sec_token_9f82d1a4e76c"
    }
    if not api_key or api_key not in valid_keys:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-Ingest-Key authentication header.",
            headers={"WWW-Authenticate": "ApiKey"}
        )
    return api_key

def sanitize_credential(value: str) -> str:
    """
    Defense-in-depth sanitization: masks passwords or credentials if present in string.
    """
    if not value:
        return ""
    # Always mask passwords uploaded to public frontend cloud
    return "*****"
