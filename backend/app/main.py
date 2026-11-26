from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.api.investigations import router as investigations_router
from backend.app.api.uploads import router as uploads_router
from backend.app.api.analyses import router as analyses_router
from contextlib import asynccontextmanager
from backend.app.services.investigation_service import initialize_database

@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield

app = FastAPI(
    title="Universal SOC Platform API",
    description="Backend API for security event analysis and SOC operations.",
    version="0.2.0",
    lifespan=lifespan,
)

# Allow the local React development server.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "ok",
        "service": "soc-platform-api",
    }


app.include_router(uploads_router)
app.include_router(analyses_router)
app.include_router(investigations_router)