import os
import io
import json
from flask import Blueprint, render_template, request, flash, current_app
from flask_login import current_user
from app import db
from app.models import ScanHistory
from app.services.qr_service import scan_qr_and_analyze

qr_scanner_bp = Blueprint('qr_scanner', __name__)

@qr_scanner_bp.route('/', methods=['GET', 'POST'])
def index():
    result = None

    if request.method == 'POST':
        file = request.files.get('qr_image')
        sample_choice = request.form.get('sample_choice')

        image_bytes = None
        filename_label = 'QR Scan'

        if file and file.filename:
            ext = os.path.splitext(file.filename)[1].lower()
            if ext not in current_app.config['ALLOWED_IMAGE_EXTENSIONS']:
                flash('Unsupported image format. Allowed formats: PNG, JPG, JPEG, WEBP, BMP.', 'danger')
                return render_template('tools/qr_scanner.html', result=None)
            image_bytes = file.read()
            filename_label = file.filename
        elif sample_choice:
            # Read generated sample QR
            sample_path = os.path.join(current_app.root_path, 'static', 'img', f'sample_{sample_choice}.png')
            if os.path.exists(sample_path):
                with open(sample_path, 'rb') as f:
                    image_bytes = f.read()
                filename_label = f"Sample QR ({sample_choice})"

        if not image_bytes:
            flash('Please upload a QR code image or select a sample QR code.', 'warning')
        else:
            model_path = current_app.config['MODEL_PATH']
            result = scan_qr_and_analyze(image_bytes, model_path)

            if result.get('success') and current_user.is_authenticated:
                target_str = (result.get('decoded_url') or filename_label)[:250]
                history_entry = ScanHistory(
                    user_id=current_user.id,
                    tool_type='qr',
                    target=target_str,
                    verdict=result.get('verdict', 'Scanned'),
                    risk_score=result.get('risk_score', 0.0),
                    details_json=json.dumps({
                        'decoded_url': result.get('decoded_url'),
                        'is_url': result.get('is_url'),
                        'top_contributions': result.get('top_contributions', [])
                    })
                )
                db.session.add(history_entry)
                db.session.commit()

    return render_template('tools/qr_scanner.html', result=result)
