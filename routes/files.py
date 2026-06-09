# routes/files.py
import os
import uuid
import hashlib
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import Response
from sqlalchemy.orm import Session
from database import get_db, EncryptedFileDB, log_action, CaseDB
from auth import get_current_user
from encryption import EncryptionService, load_key_from_env
from dotenv import load_dotenv

load_dotenv()

router = APIRouter(tags=["Files"])
enc = EncryptionService(load_key_from_env())
UPLOAD_DIR = "uploads"


@router.post("/cases/{case_id}/files", status_code=201)
async def upload_file(
    case_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Upload a file — encrypted before saving to disk."""
    case = db.query(CaseDB).filter(CaseDB.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Read file bytes
    contents = await file.read()

    # SHA-256 hash of original file (before encryption)
    integrity_hash = hashlib.sha256(contents).hexdigest()

    # Encrypt the file bytes
    encrypted = enc.encrypt(contents.decode("latin-1"))

    # Save encrypted file to disk
    file_id = str(uuid.uuid4())
    stored_filename = f"{file_id}.enc"
    filepath = os.path.join(UPLOAD_DIR, stored_filename)

    with open(filepath, "w") as f:
        f.write(encrypted)

    # Save metadata to database
    record = EncryptedFileDB(
        file_id          =file_id,
        case_id          =case_id,
        original_filename=file.filename,
        stored_filename  =stored_filename,
        file_size_bytes  =len(contents),
        integrity_hash   =integrity_hash,
        uploaded_by      =current_user["sub"],
    )
    db.add(record)
    db.commit()

    log_action(db, current_user["sub"], "UPLOAD_FILE", f"file:{file_id}")

    return {
        "file_id"          : file_id,
        "case_id"          : case_id,
        "original_filename": file.filename,
        "file_size_bytes"  : len(contents),
        "integrity_hash"   : integrity_hash,
        "uploaded_by"      : current_user["sub"],
        "uploaded_at"      : record.uploaded_at,
        "message"          : "File encrypted and stored successfully"
    }


@router.get("/cases/{case_id}/files/{file_id}")
def download_file(
    case_id: str,
    file_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Download a file — decrypted on the fly."""
    record = db.query(EncryptedFileDB).filter(
        EncryptedFileDB.file_id == file_id,
        EncryptedFileDB.case_id == case_id
    ).first()

    if not record:
        raise HTTPException(status_code=404, detail="File not found")

    # Read encrypted file from disk
    filepath = os.path.join(UPLOAD_DIR, record.stored_filename)
    with open(filepath, "r") as f:
        encrypted = f.read()

    # Decrypt
    decrypted = enc.decrypt(encrypted).encode("latin-1")

    # Verify integrity
    check_hash = hashlib.sha256(decrypted).hexdigest()
    if check_hash != record.integrity_hash:
        raise HTTPException(status_code=500, detail="File integrity check failed")

    log_action(db, current_user["sub"], "DOWNLOAD_FILE", f"file:{file_id}")

    return Response(
        content=decrypted,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={record.original_filename}"}
    )