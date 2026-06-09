# database.py
import uuid
import hashlib
from datetime import datetime
from sqlalchemy import create_engine, Column, String, DateTime, Text, Float, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
from encryption import EncryptionService, load_key_from_env

load_dotenv()

DATABASE_URL = "sqlite:///./forensic_vault.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

enc = EncryptionService(load_key_from_env())


# ── Tables ───────────────────────────────────────────────────

class UserDB(Base):
    __tablename__ = "users"
    user_id       = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username      = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role          = Column(String, default="analyst")
    created_at    = Column(DateTime, default=datetime.utcnow)


class CaseDB(Base):
    __tablename__ = "cases"
    case_id     = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    title       = Column(String, nullable=False)
    victim_name = Column(Text, nullable=False)    # encrypted
    location    = Column(Text, nullable=False)    # encrypted
    notes       = Column(Text, nullable=False)    # encrypted
    status      = Column(String, default="open")
    created_by  = Column(String, nullable=False)
    created_at  = Column(DateTime, default=datetime.utcnow)


class FingerprintSampleDB(Base):
    __tablename__ = "fingerprint_samples"
    sample_id           = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id             = Column(String, nullable=False)
    collection_method   = Column(String, nullable=False)
    decomposition_stage = Column(String, nullable=False)
    instrument          = Column(String, nullable=False)
    collection_notes    = Column(Text, nullable=False)    # encrypted
    pmi_estimate_hours  = Column(Float, nullable=True)
    temperature_celsius = Column(Float, nullable=True)
    collected_by        = Column(String, nullable=False)
    collected_at        = Column(DateTime, default=datetime.utcnow)
    integrity_hash      = Column(String, nullable=False)  # SHA-256 of original notes


class EncryptedFileDB(Base):
    __tablename__ = "encrypted_files"
    file_id           = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id           = Column(String, nullable=False)
    original_filename = Column(String, nullable=False)
    stored_filename   = Column(String, nullable=False)    # encrypted filename on disk
    file_size_bytes   = Column(Integer, nullable=False)
    integrity_hash    = Column(String, nullable=False)    # SHA-256 of original file
    uploaded_by       = Column(String, nullable=False)
    uploaded_at       = Column(DateTime, default=datetime.utcnow)


class AuditLogDB(Base):
    __tablename__ = "audit_logs"
    log_id    = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user      = Column(String, nullable=False)
    action    = Column(String, nullable=False)
    resource  = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)


# ── Init ─────────────────────────────────────────────────────

def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Audit helper ─────────────────────────────────────────────

def log_action(db, user: str, action: str, resource: str):
    entry = AuditLogDB(
        log_id   =str(uuid.uuid4()),
        user     =user,
        action   =action,
        resource =resource
    )
    db.add(entry)
    db.commit()


# ── Case helpers ─────────────────────────────────────────────

def create_case(db, case_data, created_by: str) -> CaseDB:
    new_case = CaseDB(
        case_id    =str(uuid.uuid4()),
        title      =case_data.title,
        victim_name=enc.encrypt(case_data.victim_name),
        location   =enc.encrypt(case_data.location),
        notes      =enc.encrypt(case_data.notes),
        status     =case_data.status,
        created_by =created_by,
    )
    db.add(new_case)
    db.commit()
    db.refresh(new_case)
    return new_case


def decrypt_case(case: CaseDB) -> dict:
    return {
        "case_id"    : case.case_id,
        "title"      : case.title,
        "victim_name": enc.decrypt(case.victim_name),
        "location"   : enc.decrypt(case.location),
        "notes"      : enc.decrypt(case.notes),
        "status"     : case.status,
        "created_by" : case.created_by,
        "created_at" : case.created_at,
    }


# ── Sample helpers ───────────────────────────────────────────

def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def create_sample(db, case_id: str, sample_data, collected_by: str) -> FingerprintSampleDB:
    notes_hash = sha256(sample_data.collection_notes)
    sample = FingerprintSampleDB(
        sample_id          =str(uuid.uuid4()),
        case_id            =case_id,
        collection_method  =sample_data.collection_method,
        decomposition_stage=sample_data.decomposition_stage,
        instrument         =sample_data.instrument,
        collection_notes   =enc.encrypt(sample_data.collection_notes),  # encrypt
        pmi_estimate_hours =sample_data.pmi_estimate_hours,
        temperature_celsius=sample_data.temperature_celsius,
        collected_by       =collected_by,
        integrity_hash     =notes_hash,
    )
    db.add(sample)
    db.commit()
    db.refresh(sample)
    return sample


def decrypt_sample(sample: FingerprintSampleDB) -> dict:
    return {
        "sample_id"          : sample.sample_id,
        "case_id"            : sample.case_id,
        "collection_method"  : sample.collection_method,
        "decomposition_stage": sample.decomposition_stage,
        "instrument"         : sample.instrument,
        "collection_notes"   : enc.decrypt(sample.collection_notes),  # decrypt
        "pmi_estimate_hours" : sample.pmi_estimate_hours,
        "temperature_celsius": sample.temperature_celsius,
        "collected_by"       : sample.collected_by,
        "collected_at"       : sample.collected_at,
        "integrity_hash"     : sample.integrity_hash,
    }