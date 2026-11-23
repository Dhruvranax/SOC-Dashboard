
from fastapi import FastAPI

from backend.app.api.uploads import router as uploads_router

app = FastAPI(
    title="Universal SOC Platform API",
    description="Backend API for security event analysis and SOC operations.",
    version="0.1.0",
)


@app.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "ok",
        "service": "soc-platform-api",
    }


app.include_router(uploads_router)
