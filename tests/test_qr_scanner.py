import os
from app.services.qr_service import decode_qr_image, scan_qr_and_analyze

def test_qr_decode_and_analyze(app):
    sample_safe = os.path.join(app.root_path, 'static', 'img', 'sample_safe.png')
    assert os.path.exists(sample_safe)

    with open(sample_safe, 'rb') as f:
        img_bytes = f.read()

    success, payload = decode_qr_image(img_bytes)
    assert success is True
    assert 'wikipedia.org' in payload

    analysis = scan_qr_and_analyze(img_bytes, app.config['MODEL_PATH'])
    assert analysis['success'] is True
    assert analysis['is_url'] is True
    assert analysis['decoded_url'] == payload
    assert analysis['verdict'] == 'Safe'

def test_qr_route(client):
    res = client.get('/qr-scanner/')
    assert res.status_code == 200
    assert b'QR Phishing (Quishing) Scanner' in res.data
