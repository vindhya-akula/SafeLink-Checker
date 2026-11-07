
import json
import ipaddress

from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ScanHistory
from app.services.url_analyzer import analyze_url
from app.services.virustotal import check_virustotal


router = APIRouter(prefix="/api", tags=["Scanner"])


# Request data validation
class URLRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)


# Validate submitted URLs
def validate_url(value: str):

    try:
        if any(character.isspace() for character in value):
            raise ValueError("URL must not contain whitespace.")

        parsed = urlsplit(value)

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS URLs are allowed.")

        hostname = parsed.hostname

        if not hostname:
            raise ValueError("A valid hostname is required.")

        if parsed.username or parsed.password:
            raise ValueError("URLs containing credentials are not allowed.")

        # Accessing port also validates its format and range.
        _ = parsed.port

        hostname = hostname.rstrip(".").lower()

        if hostname == "localhost" or hostname.endswith(".localhost"):
            raise ValueError("Localhost URLs are not supported.")

        if hostname.endswith((".local", ".internal")):
            raise ValueError("Local network hostnames are not supported.")

        # Check whether hostname is an IP address.
        try:
            ip = ipaddress.ip_address(hostname)

            if not ip.is_global:
                raise ValueError(
                    "Private or non-public IP addresses are not supported."
                )

        except ValueError as ip_error:
            # Distinguish an ordinary domain from our custom IP rejection.
            if "Private or non-public" in str(ip_error):
                raise

            # Validate basic domain structure.
            if "." not in hostname:
                raise ValueError(
                    "Please enter a fully qualified domain name."
                )

            if len(hostname) > 253:
                raise ValueError("Hostname is too long.")

        return parsed

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


# Endpoint 1: Analyze URL and save scan history
@router.post("/scan")
def scan_url(
    request: URLRequest,
    db: Session = Depends(get_db)
):

    validate_url(request.url)

    analysis = analyze_url(request.url)

    record = ScanHistory(
        url=request.url,
        risk_score=analysis["risk_score"],
        risk_level=analysis["risk_level"],
        status=analysis["risk_level"],
        findings=json.dumps(analysis["findings"]),
        created_at=datetime.now(timezone.utc)
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    return {
        "scan_id": record.id,
        "url": request.url,
        **analysis,
        "scanned_at": record.created_at.isoformat()
    }


# Endpoint 2: Explicit VirusTotal check
@router.post("/threat-intel")
async def threat_intelligence(request: URLRequest):

    validate_url(request.url)

    result = await check_virustotal(request.url)

    if result["status"] == "not_configured":
        raise HTTPException(status_code=503, detail=result["message"])

    if result["status"] == "authentication_error":
        raise HTTPException(status_code=502, detail=result["message"])

    if result["status"] == "access_denied":
        raise HTTPException(status_code=502, detail=result["message"])

    if result["status"] == "rate_limited":
        raise HTTPException(status_code=429, detail=result["message"])

    if result["status"] in ("timeout", "connection_error", "api_error"):
        raise HTTPException(status_code=502, detail=result["message"])

    return {
        "url": request.url,
        **result
    }


# Endpoint 3: Retrieve recent scan history
@router.get("/history")
def scan_history(db: Session = Depends(get_db)):

    records = (
        db.query(ScanHistory)
        .order_by(ScanHistory.id.desc())
        .limit(50)
        .all()
    )

    return [
        {
            "id": record.id,
            "url": record.url,
            "risk_score": record.risk_score,
            "risk_level": record.risk_level,
            "created_at": record.created_at.isoformat()
        }
        for record in records
    ]
