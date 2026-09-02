from fastapi import APIRouter, HTTPException

from app.services.proxy_check import check_proxy


router = APIRouter(
    prefix="/proxy",
    tags=["Proxy Intelligence"]
)


@router.get("/{ip}")
def proxy_check(ip: str):
    result = check_proxy(ip)

    if result.get("error"):
        raise HTTPException(
            status_code=502,
            detail=result["error"]
        )

    return result