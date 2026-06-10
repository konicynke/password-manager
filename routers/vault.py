from fastapi import APIRouter, Request, Depends
from sqlalchemy.orm import Session

from database import get_db
from schemas import VaultItemData, VaultItemUpdate
from services.vault_service import (
    add_new_vault_item, get_vault_items, 
    update_vault_item, delete_vault_item, audit_passwords
)

router = APIRouter(prefix="/vault", tags=["Vault"])

@router.get("/")
async def vault_get(request: Request, db: Session = Depends(get_db)):
    return get_vault_items(request, db)

@router.get("/audit")
async def vault_audit_get(request: Request, db: Session = Depends(get_db)):
    return audit_passwords(request, db)

@router.post("/")
async def vault_post(data: VaultItemData, request: Request, db: Session = Depends(get_db)):
    return add_new_vault_item(data.model_dump(), request, db)

@router.delete("/{item_id}")
async def vault_delete(item_id: int, request: Request, db: Session = Depends(get_db)):
    return delete_vault_item(item_id, request, db)

@router.patch("/{item_id}")
async def vault_patch(item_id: int, data: VaultItemUpdate, request: Request, db: Session = Depends(get_db)):
    return update_vault_item(item_id, data.model_dump(), request, db)