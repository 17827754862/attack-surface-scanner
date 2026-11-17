from fastapi import APIRouter, Depends

from ..capabilities import read_capabilities
from ..security import get_current_user


router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/api/capabilities")
def capabilities(_user=Depends(get_current_user)) -> dict:
    return read_capabilities()
