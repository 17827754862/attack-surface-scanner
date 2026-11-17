from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import User, get_db
from ..schemas.task import LoginRequest, TokenResponse
from ..security import create_access_token, verify_password


router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = db.query(User).filter(User.username == payload.username).first()
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="invalid username or password")
    return TokenResponse(access_token=create_access_token(user.username))
