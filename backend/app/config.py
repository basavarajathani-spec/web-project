import os

APP_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(APP_DIR)

UPLOADS_DIR = os.path.join(BACKEND_DIR, "uploads")
OUTPUTS_DIR = os.path.join(BACKEND_DIR, "outputs")

os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(OUTPUTS_DIR, exist_ok=True)

# Basic upload guardrails (spec calls for "Maximum Upload Size" under Security Features)
MAX_IMAGE_SIZE_MB = 20
MAX_VIDEO_SIZE_MB = 200
