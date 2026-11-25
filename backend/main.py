from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.api.routes import router


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIRECTORY = PROJECT_ROOT / "frontend"

app = FastAPI(
    title="IPv6 Readiness Auditor",
    description="Browser-based website resource measurement dashboard.",
)
app.include_router(router)
app.mount("/static", StaticFiles(directory=FRONTEND_DIRECTORY), name="static")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(FRONTEND_DIRECTORY / "index.html")
