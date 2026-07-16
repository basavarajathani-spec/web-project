# Core Engine: AES Encryption + LSB Video Steganography

This is the crypto/CV heart of the "Secure Image Transmission" project, built
and verified first because it's the part where bugs actually break the
project (a broken auth route just returns a 500; a broken steganography
implementation silently corrupts every file).

## What's here

```
backend/
├── encryption/
│   ├── aes_encrypt.py    # AES-256-CBC encrypt + SHA-256 of plaintext + key gen
│   └── aes_decrypt.py    # AES-256-CBC decrypt + SHA-256 integrity verification
├── steganography/
│   ├── payload.py        # Shared header format (MAGIC + IV + SHA256 + LEN)
│   ├── embed.py          # Embeds AES ciphertext into a cover video via LSB
│   └── extract.py        # Extracts it back out
├── tests/
│   └── test_roundtrip.py # Full pipeline test, generates its own sample files
└── requirements.txt
```

## Run it yourself

```bash
pip install -r requirements.txt
python3 tests/test_roundtrip.py
```

This generates a synthetic secret image and cover video, runs
`encrypt -> embed -> extract -> decrypt`, and asserts the recovered image is
**byte-for-byte identical** to the original with SHA-256 integrity confirmed.
Verified passing, including two failure-mode checks (oversized payload
correctly rejected with a clear capacity error; wrong decryption key
correctly rejected rather than silently returning garbage).

## Design decisions you should know about (for your report/viva too)

**1. Lossless codec is mandatory.** Stego videos are written with the `FFV1`
lossless codec into a `.avi` container. This is not optional — H.264/MP4 and
other delivery codecs are lossy, and *any* re-compression destroys LSB data.
This is the single most common way student steganography projects silently
fail (it "works" on the exact file just written, then breaks the moment the
video is re-encoded or uploaded through something that transcodes it). If
your spec/demo needs an MP4 for the "download stego video" button, that's a
UX decision to surface to the user (e.g. "download lossless .avi for
decryption" vs. a separate lossy MP4 preview) — don't let the frontend
silently re-encode the real file.

**2. Payload framing.** Each embed writes a 56-byte header (magic bytes, the
AES IV, the SHA-256 of the *original* image, and ciphertext length) before
the ciphertext itself, all bit-packed into pixel LSBs across B/G/R channels,
frame by frame. This means extraction doesn't need to know the payload size
in advance, and a corrupted/wrong video fails fast with a clear error instead
of returning garbage.

**3. Capacity checking.** `embed_data_in_video` computes exact bit capacity
(`width * height * 3 * frame_count`) before writing anything, and raises a
descriptive `ValueError` if the cover video is too small — this is the error
message your Encrypt page's progress UI should surface directly.

**4. Integrity.** SHA-256 of the plaintext image is embedded in the header
and re-checked after decryption (`decrypt_image(..., expected_sha256_hex=...)`),
so "Integrity Verification" on your Decrypt page is a real check, not just a
UI label.

## Not yet built (next steps, in priority order for your deadline)

1. **FastAPI wrapper** around these 4 functions: `POST /encrypt` (image +
   video in, stego video + key out), `POST /decrypt` (stego video + key in,
   image out). This alone gives you a working demo end-to-end.
2. Auth (JWT + bcrypt) and the SQLAlchemy models/history logging.
3. QR code generation for the AES key (small addition, ~10 lines with
   `qrcode` library).
4. Frontend pages, wired to the two core endpoints above.

Say the word and I'll build the FastAPI layer next so you have a runnable
`/encrypt` and `/decrypt` API today — that's the highest-value next step
given your deadline.
