# models.py
from pydantic import BaseModel
from typing import Optional
from datetime import datetime


# ── Auth schemas ─────────────────────────────────────────────

class UserRegister(BaseModel):
    username: str
    password: str
    role: str = "analyst"


class UserLogin(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ── Case schemas ─────────────────────────────────────────────

class CaseCreate(BaseModel):
    title: str
    victim_name: str
    location: str
    notes: str
    status: str = "open"


class CaseResponse(BaseModel):
    case_id: str
    title: str
    victim_name: str
    location: str
    notes: str
    status: str
    created_by: str
    created_at: datetime

    class Config:
        from_attributes = True


# ── Fingerprint sample schemas ───────────────────────────────

class SampleCreate(BaseModel):
    collection_method: str        # e.g. "gel lift", "sfPESI-MS direct"
    decomposition_stage: str      # fresh / early / active / advanced / skeletal
    instrument: str               # e.g. "sfPESI-MS", "DESI-MS"
    collection_notes: str         # sensitive — encrypted
    pmi_estimate_hours: Optional[float] = None  # post-mortem interval estimate
    temperature_celsius: Optional[float] = None # ambient temp at collection


class SampleResponse(BaseModel):
    sample_id: str
    case_id: str
    collection_method: str
    decomposition_stage: str
    instrument: str
    collection_notes: str         # decrypted on return
    pmi_estimate_hours: Optional[float]
    temperature_celsius: Optional[float]
    collected_by: str
    collected_at: datetime
    integrity_hash: str           # SHA-256 of original notes

    class Config:
        from_attributes = True


# ── File schemas ─────────────────────────────────────────────

class FileUploadResponse(BaseModel):
    file_id: str
    case_id: str
    original_filename: str
    file_size_bytes: int
    integrity_hash: str           # SHA-256 of original file
    uploaded_by: str
    uploaded_at: datetime

    class Config:
        from_attributes = True


# ── Audit schemas ────────────────────────────────────────────

class AuditLogResponse(BaseModel):
    log_id: str
    user: str
    action: str
    resource: str
    timestamp: datetime

    class Config:
        from_attributes = True