"""
/encrypt and /decrypt endpoints, wrapping the already-tested core modules in
encryption/ and steganography/. No auth/DB yet - this is the minimal layer
needed to make the project demo-able end-to-end from the frontend.
"""

import os
import uuid

from fastapi import APIRouter, UploadFile, File, Form, HTTPException

from encryption.aes_encrypt import encrypt_bytes, key_to_hex, key_from_hex
from encryption.aes_decrypt import decrypt_image
from steganography.embed import embed_data_in_video
from steganography.extract import extract_data_from_video

from app.config import UPLOADS_DIR, OUTPUTS_DIR, MAX_IMAGE_SIZE_MB, MAX_VIDEO_SIZE_MB

router = APIRouter()


def _save_upload(upload: UploadFile, dest_dir: str, max_size_mb: int) -> str:
    contents = upload.file.read()
    size_mb = len(contents) / (1024 * 1024)
    if size_mb > max_size_mb:
        raise HTTPException(
            status_code=413,
            detail=f"{upload.filename} is {size_mb:.1f} MB, exceeds the {max_size_mb} MB limit.",
        )
    ext = os.path.splitext(upload.filename or "")[1]
    name = f"{uuid.uuid4().hex}{ext}"
    path = os.path.join(dest_dir, name)
    with open(path, "wb") as f:
        f.write(contents)
    return path


def _guess_image_extension(data: bytes) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data.startswith(b"GIF8"):
        return ".gif"
    if data.startswith(b"BM"):
        return ".bmp"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ".webp"
    return ".bin"


@router.post("/encrypt")
async def encrypt_endpoint(
    secret_image: UploadFile = File(...),
    cover_video: UploadFile = File(...),
):
    """
    Encrypts `secret_image` with AES-256-CBC, embeds the ciphertext into
    `cover_video` via LSB steganography, and returns the AES key plus a
    download link for the resulting stego video.
    """
    image_path = _save_upload(secret_image, UPLOADS_DIR, MAX_IMAGE_SIZE_MB)
    video_path = _save_upload(cover_video, UPLOADS_DIR, MAX_VIDEO_SIZE_MB)

    try:
        with open(image_path, "rb") as f:
            enc = encrypt_bytes(f.read())

        output_name = f"stego_{uuid.uuid4().hex}.avi"
        output_path = os.path.join(OUTPUTS_DIR, output_name)

        stats = embed_data_in_video(
            video_path, enc["iv"], enc["sha256"], enc["encrypted_data"], output_path
        )
    except ValueError as e:
        # Capacity errors, bad video, etc. - these are client-fixable, so 400 not 500
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        os.remove(image_path)
        os.remove(video_path)

    return {
        "key_hex": key_to_hex(enc["key"]),
        "sha256": enc["sha256"],
        "download_url": f"/files/{output_name}",
        "stats": {
            "frames_used": stats["frames_used"],
            "total_frames": stats["total_frames"],
            "bytes_embedded": stats["bytes_embedded"],
        },
    }


@router.post("/decrypt")
async def decrypt_endpoint(
    stego_video: UploadFile = File(...),
    key_hex: str = Form(...),
):
    """
    Extracts the hidden payload from `stego_video` and decrypts it using the
    supplied AES key, returning a download link for the recovered image and
    whether the SHA-256 integrity check passed.
    """
    video_path = _save_upload(stego_video, UPLOADS_DIR, MAX_VIDEO_SIZE_MB)

    try:
        try:
            key = key_from_hex(key_hex)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        try:
            extracted = extract_data_from_video(video_path)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        try:
            result = decrypt_image(
                extracted["encrypted_data"],
                key,
                extracted["iv"],
                expected_sha256_hex=extracted["sha256"],
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        ext = _guess_image_extension(result["data"])
        output_name = f"recovered_{uuid.uuid4().hex}{ext}"
        output_path = os.path.join(OUTPUTS_DIR, output_name)
        with open(output_path, "wb") as f:
            f.write(result["data"])
    finally:
        os.remove(video_path)

    return {
        "image_url": f"/files/{output_name}",
        "integrity_ok": result["integrity_ok"],
        "stats": {
            "recovered_bytes": len(result["data"]),
        },
    }
