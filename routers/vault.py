from fastapi import APIRouter, Request

from schemas import VaultItemData, VaultItemUpdate
from services.vault_service import (
    add_new_vault_item, get_vault_items, 
    update_vault_item, delete_vault_item, audit_passwords
)

router = APIRouter(prefix="/vault", tags=["Vault"])

@router.get("/")
async def vault_get(request: Request):
    return get_vault_items(request)

@router.post("/")
async def vault_post(data: VaultItemData, request: Request):
    return add_new_vault_item(data.model_dump(), request)

@router.delete("/{item_id}")
async def vault_delete(item_id: int, request: Request):
    return delete_vault_item(item_id, request)

@router.patch("/{item_id}")
async def vault_patch(item_id: int, data: VaultItemUpdate, request: Request):
    return update_vault_item(item_id, data.model_dump(), request)

@router.get("/audit")
async def vault_audit_get(request: Request):
    return audit_passwords(request)