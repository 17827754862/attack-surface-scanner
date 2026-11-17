from __future__ import annotations

from fastapi import APIRouter, Depends

from ..auth_session import list_auth_profiles
from ..db import User
from ..security import get_current_user


router = APIRouter(prefix="/api/auth-profiles", tags=["auth-profiles"])


@router.get("")
def get_auth_profiles(_user: User = Depends(get_current_user)) -> list[dict]:
    return list_auth_profiles()
