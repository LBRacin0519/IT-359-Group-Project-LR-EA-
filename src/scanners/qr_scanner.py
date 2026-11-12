import cv2
import numpy as np


def decode_qr(image_bytes):
    """
    Decode a QR code from uploaded image bytes.

    Does not visit URLs or execute decoded content.
    """
    if not image_bytes:
        return {
            "success": False,
            "content": None,
            "error": "No image was provided."
        }

    try:
        image_array = np.frombuffer(image_bytes, dtype=np.uint8)
        image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)

        if image is None:
            raise ValueError("Unable to read the image.")

        detector = cv2.QRCodeDetector()
        content, points, _ = detector.detectAndDecode(image)

        if not content:
            return {
                "success": False,
                "content": None,
                "error": "No readable QR code was detected."
            }

        return {
            "success": True,
            "content": content,
            "error": None
        }

    except (ValueError, cv2.error) as error:
        return {
            "success": False,
            "content": None,
            "error": str(error)
        }