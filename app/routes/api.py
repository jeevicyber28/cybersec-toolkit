import os
import json
from flask import Blueprint, request, jsonify, render_template, current_app
from flask_login import current_user
from app import db
from app.models import User, ScanHistory
from app.services.ml_engine import PhishingMLEngine
from app.services.email_parser import analyze_email
from app.services.qr_service import scan_qr_and_analyze
from app.services.password_service import query_hibp_range
from app.services.safety_score import calculate_user_safety_metrics

api_bp = Blueprint('api', __name__)

def get_request_user():
    """Identifies the user from API Key header or active session."""
    api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
    if api_key:
        return User.query.filter_by(api_key=api_key).first()
    if current_user.is_authenticated:
        return current_user
    return None

@api_bp.route('/docs')
def docs():
    """Interactive OpenAPI documentation page."""
    return render_template('api_docs.html')

@api_bp.route('/v1/scan-url', methods=['POST'])
def scan_url():
    data = request.get_json(silent=True) or request.form
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'Missing required parameter: url'}), 400

    model_path = current_app.config['MODEL_PATH']
    engine = PhishingMLEngine.get_instance(model_path)
    result = engine.predict(url)

    user = get_request_user()
    if user:
        history_entry = ScanHistory(
            user_id=user.id,
            tool_type='url',
            target=url[:250],
            verdict=result['verdict'],
            risk_score=result['risk_score'],
            details_json=json.dumps({'api_call': True, 'score': result['risk_score']})
        )
        db.session.add(history_entry)
        db.session.commit()

    return jsonify({
        'status': 'success',
        'url': url,
        'verdict': result['verdict'],
        'verdict_class': result['verdict_class'],
        'risk_score': result['risk_score'],
        'phishing_probability': result['phishing_probability'],
        'top_contributions': result['top_contributions']
    })

@api_bp.route('/v1/scan-email', methods=['POST'])
def scan_email_api():
    data = request.get_json(silent=True) or request.form
    raw_content = data.get('raw_email', '').strip()
    if not raw_content:
        return jsonify({'error': 'Missing required parameter: raw_email'}), 400

    result = analyze_email(raw_content)
    user = get_request_user()
    if user:
        history_entry = ScanHistory(
            user_id=user.id,
            tool_type='email',
            target=(result['subject'] or 'Email API Scan')[:250],
            verdict=result['verdict'],
            risk_score=result['risk_score']
        )
        db.session.add(history_entry)
        db.session.commit()

    return jsonify({
        'status': 'success',
        'subject': result['subject'],
        'verdict': result['verdict'],
        'risk_score': result['risk_score'],
        'authentication': result['authentication'],
        'hops_count': len(result['hops']),
        'link_mismatches': result['link_mismatches'],
        'risky_attachments': result['risky_attachments']
    })

@api_bp.route('/v1/scan-qr', methods=['POST'])
def scan_qr_api():
    file = request.files.get('qr_image')
    if not file:
        return jsonify({'error': 'Missing uploaded file: qr_image'}), 400

    image_bytes = file.read()
    model_path = current_app.config['MODEL_PATH']
    result = scan_qr_and_analyze(image_bytes, model_path)

    if not result.get('success'):
        return jsonify({'status': 'error', 'message': result.get('error', 'Decoding failed')}), 422

    user = get_request_user()
    if user:
        history_entry = ScanHistory(
            user_id=user.id,
            tool_type='qr',
            target=(result.get('decoded_url') or 'QR Code')[:250],
            verdict=result.get('verdict', 'Scanned'),
            risk_score=result.get('risk_score', 0.0)
        )
        db.session.add(history_entry)
        db.session.commit()

    return jsonify({
        'status': 'success',
        'is_url': result.get('is_url', False),
        'decoded_url': result.get('decoded_url'),
        'verdict': result.get('verdict'),
        'risk_score': result.get('risk_score'),
        'warning': result.get('warning')
    })

@api_bp.route('/v1/pwned-range/<prefix>', methods=['GET'])
def pwned_range(prefix):
    """
    K-Anonymity endpoint.
    Strictly forwards the 5-character prefix to HIBP.
    """
    success, data = query_hibp_range(prefix)
    if not success:
        return jsonify({'status': 'error', 'message': data}), 400

    return data, 200, {'Content-Type': 'text/plain'}

@api_bp.route('/v1/game/items', methods=['GET'])
def game_items():
    path = current_app.config['GAME_ITEMS_PATH']
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            items = json.load(f)
        return jsonify({'status': 'success', 'items': items})
    return jsonify({'status': 'error', 'message': 'Items file not found'}), 404

@api_bp.route('/v1/safety-score', methods=['GET'])
def safety_score():
    user = get_request_user()
    metrics = calculate_user_safety_metrics(user.id if user else None)
    return jsonify({'status': 'success', 'metrics': metrics})
