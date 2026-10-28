from flask import Blueprint, render_template, request, flash
from flask_login import current_user
from app.services.ssl_headers_service import analyze_headers_and_ssl
from app.models import ScanHistory
from app import db

ssl_headers_bp = Blueprint('ssl_headers', __name__)

@ssl_headers_bp.route('/', methods=['GET', 'POST'])
def index():
    result = None
    target_input = ''

    if request.method == 'POST':
        target_input = request.form.get('target', '').strip()
        if not target_input:
            flash('Please enter a valid domain or URL.', 'warning')
        else:
            result = analyze_headers_and_ssl(target_input)

            # Record in history if user authenticated
            if current_user.is_authenticated:
                try:
                    history = ScanHistory(
                        user_id=current_user.id,
                        scan_type='SSL/Headers',
                        target=result.get('hostname') or target_input,
                        verdict=f"Grade {result.get('grade')}",
                        risk_score=100 - result.get('score', 0),
                        details={
                            'grade': result.get('grade'),
                            'score': result.get('score'),
                            'ssl_version': result.get('ssl_info', {}).get('version'),
                            'warnings_count': len(result.get('warnings', []))
                        }
                    )
                    db.session.add(history)
                    db.session.commit()
                except Exception:
                    db.session.rollback()

    return render_template('tools/ssl_headers.html', result=result, target_input=target_input)
