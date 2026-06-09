# routes/auth.py
# Register and login endpoints

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database import get_db, UserDB
from models import UserRegister, UserLogin, TokenResponse
from auth import hash_password, verify_password, create_token
import uuid

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", status_code=201)
def register(user: UserRegister, db: Session = Depends(get_db)):
    """Register a new forensic analyst account."""

    # Check username not already taken
    existing = db.query(UserDB).filter(UserDB.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    new_user = UserDB(
        user_id      =str(uuid.uuid4()),
        username     =user.username,
        password_hash=hash_password(user.password),
        role         =user.role,
    )
    db.add(new_user)
    db.commit()
    return {"message": f"User '{user.username}' registered successfully"}


@router.post("/login", response_model=TokenResponse)
def login(user: UserLogin, db: Session = Depends(get_db)):
    """Login and receive a JWT token."""

    db_user = db.query(UserDB).filter(UserDB.username == user.username).first()

    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    token = create_token(db_user.username, db_user.role)
    return {"access_token": token, "token_type": "bearer"}