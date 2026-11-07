
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, DateTime, Text

from app.database import Base


class ScanHistory(Base):

    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)

    url = Column(String(2048), nullable=False)

    risk_score = Column(Integer, nullable=False)

    risk_level = Column(String(30), nullable=False)

    status = Column(String(50), nullable=False)

    findings = Column(Text, nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
