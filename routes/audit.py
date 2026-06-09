# routes/audit.py
# Audit log endpoint — admin only

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database import get_db, AuditLogDB
from models import AuditLogResponse
from auth import get_current_user
from typing import List

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("", response_model=List[AuditLogResponse])
def get_audit_log(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """View the full audit log — every access ever made."""
    logs = db.query(AuditLogDB).order_by(AuditLogDB.timestamp.desc()).all()
    return logs