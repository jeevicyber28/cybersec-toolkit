import json
from flask import Blueprint, render_template, request, jsonify
from flask_login import current_user
from app import db
from app.models import ScanHistory
from app.services.password_service import evaluate_password_strength

password_checker_bp = Blueprint('password_checker', __name__)

@password_checker_bp.route('/')
def index():
    return render_template('tools/password_checker.html')

@password_checker_bp.route('/evaluate', methods=['POST'])
def evaluate():
    """
    Defensive endpoint for local entropy and pattern calculation.
    Zero-Knowledge: Full password is never persisted or logged.
    """
    data = request.get_json() or {}
    password = data.get('password', '')
    evaluation = evaluate_password_strength(password)
    return jsonify(evaluation)

@password_checker_bp.route('/record-audit', methods=['POST'])
def record_audit():
    """
    Saves an anonymous audit summary to history.
    NEVER accepts or stores the password, hash, or prefix.
    """
    if not current_user.is_authenticated:
        return jsonify({'success': False, 'message': 'Authentication required to save history'}), 401

    data = request.get_json() or {}
    rating = data.get('rating', 'Moderate')
    entropy_bits = data.get('entropy_bits', 0)
    pwned_count = data.get('pwned_count', 0)
    score = data.get('score', 50)

    verdict = 'Malicious (Pwned)' if pwned_count > 0 else rating
    risk_score = 90.0 if pwned_count > 0 else max(5.0, 100.0 - score)

    target_summary = f"Password Audit (Entropy: {entropy_bits} bits, Breached: {'YES (' + str(pwned_count) + ' times)' if pwned_count > 0 else 'NO'})"

    history_entry = ScanHistory(
        user_id=current_user.id,
        tool_type='password',
        target=target_summary,
        verdict=verdict,
        risk_score=risk_score,
        details_json=json.dumps({
            'entropy_bits': entropy_bits,
            'pwned_count': pwned_count,
            'rating': rating,
            'security_tips': data.get('tips', [])
        })
    )
    db.session.add(history_entry)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Audit recorded to history without storing password.'})
