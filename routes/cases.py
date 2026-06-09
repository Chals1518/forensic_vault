# routes/cases.py
# Case CRUD endpoints — all protected by JWT

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db, CaseDB, create_case, decrypt_case, log_action
from models import CaseCreate, CaseResponse
from auth import get_current_user
from typing import List

router = APIRouter(prefix="/cases", tags=["Cases"])


@router.post("", status_code=201)
def new_case(
    case: CaseCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create a new case — encrypts sensitive fields before saving."""
    saved = create_case(db, case, current_user["sub"])
    log_action(db, current_user["sub"], "CREATE", f"case:{saved.case_id}")
    return decrypt_case(saved)


@router.get("", response_model=List[CaseResponse])
def list_cases(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """List all cases — decrypts each one before returning."""
    cases = db.query(CaseDB).all()
    log_action(db, current_user["sub"], "LIST", "cases:all")
    return [decrypt_case(c) for c in cases]


@router.get("/{case_id}", response_model=CaseResponse)
def get_case(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get a single case by ID — decrypts on read."""
    case = db.query(CaseDB).filter(CaseDB.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    log_action(db, current_user["sub"], "READ", f"case:{case_id}")
    return decrypt_case(case)


@router.delete("/{case_id}")
def delete_case(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Delete a case — logs deletion to audit trail."""
    case = db.query(CaseDB).filter(CaseDB.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    db.delete(case)
    db.commit()
    log_action(db, current_user["sub"], "DELETE", f"case:{case_id}")
    return {"message": f"Case {case_id} deleted"}