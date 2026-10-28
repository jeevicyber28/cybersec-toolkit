import os
import io
import cv2
import numpy as np
from PIL import Image
from app.services.ml_engine import PhishingMLEngine

def decode_qr_image(image_bytes):
    """
    Decodes QR code from raw image bytes using OpenCV and PIL.
    Returns (success, decoded_text_or_error)
    """
    try:
        # Load image via PIL to handle diverse formats (.png, .jpg, .webp, .bmp)
        pil_img = Image.open(io.BytesIO(image_bytes))
        # Convert to RGB if needed
        if pil_img.mode != 'RGB':
            pil_img = pil_img.convert('RGB')
        
        # Convert to OpenCV BGR format
        cv_img = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)

        # Pre-process: if image is small (e.g. < 200px), upscale and add quiet zone border
        h, w = cv_img.shape[:2]
        if max(h, w) < 250:
            scale_factor = max(2, int(300 / max(h, w, 1)))
            cv_img = cv2.resize(cv_img, (w * scale_factor, h * scale_factor), interpolation=cv2.INTER_NEAREST)
            cv_img = cv2.copyMakeBorder(cv_img, 20, 20, 20, 20, cv2.BORDER_CONSTANT, value=[255, 255, 255])

        # 1. OpenCV QRCodeDetector
        detector = cv2.QRCodeDetector()
        val, pts, straight_qrcode = detector.detectAndDecode(cv_img)
        if val and val.strip():
            return True, val.strip()

        # 2. Try grayscale + thresholding if initial detection fails
        gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
        val, pts, _ = detector.detectAndDecode(gray)
        if val and val.strip():
            return True, val.strip()

        # 3. Adaptive thresholding for noisy/low-contrast photos
        thresh = cv2.adaptiveThreshold(
            gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
        )
        val, pts, _ = detector.detectAndDecode(thresh)
        if val and val.strip():
            return True, val.strip()

        return False, "No QR code could be detected in this image. Please ensure the QR is clear and well-lit."
    except Exception as e:
        return False, f"Image processing error: {str(e)}"


def scan_qr_and_analyze(image_bytes, model_path=None):
    """
    Decodes the QR image server-side, extracts payload, runs phishing detector if URL,
    and returns comprehensive safety report.
    """
    success, result = decode_qr_image(image_bytes)
    if not success:
        return {
            'success': False,
            'error': result,
            'decoded_url': None,
            'verdict': 'Error',
            'verdict_class': 'secondary',
            'risk_score': 0,
            'is_url': False
        }

    decoded_payload = result
    is_url = bool(decoded_payload.startswith(('http://', 'https://', 'www.')) or '.' in decoded_payload)

    if is_url:
        ml_engine = PhishingMLEngine.get_instance(model_path)
        analysis = ml_engine.predict(decoded_payload)
        return {
            'success': True,
            'is_url': True,
            'decoded_url': decoded_payload,
            'verdict': analysis['verdict'],
            'verdict_class': analysis['verdict_class'],
            'risk_score': analysis['risk_score'],
            'phishing_probability': analysis['phishing_probability'],
            'top_contributions': analysis['top_contributions'],
            'features': analysis['features'],
            'warning': 'Caution: Never open QR links directly. Review the destination domain and parameters.'
        }
    else:
        # Plain text QR
        return {
            'success': True,
            'is_url': False,
            'decoded_url': decoded_payload,
            'verdict': 'Safe (Text payload)',
            'verdict_class': 'success',
            'risk_score': 5.0,
            'warning': 'This QR code contains plain text, not an executable URL.'
        }
