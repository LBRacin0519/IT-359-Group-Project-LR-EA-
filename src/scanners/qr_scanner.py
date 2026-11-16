"""Decode QR images locally, without opening decoded URLs or content."""

import cv2
import numpy as np

MAX_QR_IMAGE_BYTES = 8 * 1024 * 1024


def decode_qr(image_bytes):
    """Return {'success', 'content', 'error'}; decoded text is untrusted."""
    if not isinstance(image_bytes, bytes) or not image_bytes:
        return {"success": False, "content": None, "error": "No QR image was provided."}
    if len(image_bytes) > MAX_QR_IMAGE_BYTES:
        return {"success": False, "content": None, "error": "QR image exceeds the 8 MiB limit."}
    try:
        image = cv2.imdecode(np.frombuffer(image_bytes, dtype=np.uint8), cv2.IMREAD_COLOR)
        if image is None:
            return {"success": False, "content": None, "error": "Image could not be decoded."}
        if image.shape[0] * image.shape[1] > 20_000_000:
            return {"success": False, "content": None, "error": "QR image resolution is too large."}
        content, _, _ = cv2.QRCodeDetector().detectAndDecode(image)
        if not content:
            return {"success": False, "content": None, "error": "No readable QR code was found."}
        if len(content) > 8192:
            return {"success": False, "content": None, "error": "Decoded QR content exceeds the supported length."}
        return {"success": True, "content": content, "error": None}
    except (ValueError, cv2.error, MemoryError):
        return {"success": False, "content": None, "error": "Unable to process the uploaded QR image."}
