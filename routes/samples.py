# routes/samples.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db, FingerprintSampleDB, create_sample, decrypt_sample, log_action, CaseDB
from models import SampleCreate, SampleResponse
from auth import get_current_user
from typing import List

router = APIRouter(tags=["Fingerprint samples"])


@router.post("/cases/{case_id}/samples", status_code=201)
def add_sample(
    case_id: str,
    sample: SampleCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Add a fingerprint sample record to a case."""
    case = db.query(CaseDB).filter(CaseDB.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    saved = create_sample(db, case_id, sample, current_user["sub"])
    log_action(db, current_user["sub"], "CREATE_SAMPLE", f"sample:{saved.sample_id}")
    return decrypt_sample(saved)


@router.get("/cases/{case_id}/samples", response_model=List[SampleResponse])
def list_samples(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """List all fingerprint samples for a case."""
    samples = db.query(FingerprintSampleDB).filter(
        FingerprintSampleDB.case_id == case_id
    ).all()
    log_action(db, current_user["sub"], "LIST_SAMPLES", f"case:{case_id}")
    return [decrypt_sample(s) for s in samples]


@router.get("/cases/{case_id}/samples/{sample_id}", response_model=SampleResponse)
def get_sample(
    case_id: str,
    sample_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get a single fingerprint sample."""
    sample = db.query(FingerprintSampleDB).filter(
        FingerprintSampleDB.sample_id == sample_id,
        FingerprintSampleDB.case_id == case_id
    ).first()
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    log_action(db, current_user["sub"], "READ_SAMPLE", f"sample:{sample_id}")
    return decrypt_sample(sample)