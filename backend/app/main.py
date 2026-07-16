"""
FastAPI entrypoint.

Run from the `backend/` directory:
    uvicorn app.main:app --reload --port 8000

Serves:
    POST /encrypt         (see app/routes.py)
    POST /decrypt         (see app/routes.py)
    GET  /files/{name}    downloads for generated stego videos / recovered images
"""

import os
import sys

# Make sure `backend/` (the parent of this `app/` package) is importable
# regardless of how/where this is launched from, so `from encryption...`
# and `from steganography...` always resolve.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.routes import router
from app.config import OUTPUTS_DIR

app = FastAPI(
    title="Secure Image Transmission API",
    description="AES-256 encryption + LSB video steganography",
    version="0.1.0",
)

# The frontend dev server (Vite, port 5173) calls this API directly in some
# setups, and through a proxy in others (see frontend/vite.config.js). CORS
# is left open here for local development; tighten `allow_origins` before
# deploying anywhere public.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

# Serves generated stego videos and recovered images for direct download,
# e.g. GET /files/stego_ab12cd.avi
app.mount("/files", StaticFiles(directory=OUTPUTS_DIR), name="files")


@app.get("/health")
def health():
    return {"status": "ok"}
