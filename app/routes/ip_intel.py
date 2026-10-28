from flask import Blueprint, render_template, request, flash
from flask_login import current_user
from app.services.ip_intel_service import analyze_ip_and_domain
from app.models import ScanHistory
from app import db

ip_intel_bp = Blueprint('ip_intel', __name__)

@ip_intel_bp.route('/', methods=['GET', 'POST'])
def index():
    result = None
    query_input = ''

    if request.method == 'POST':
        query_input = request.form.get('query', '').strip()
        if not query_input:
            flash('Please enter an IP address or domain name.', 'warning')
        else:
            result = analyze_ip_and_domain(query_input)

            if result.get('error'):
                flash(result['error'], 'danger')
            elif current_user.is_authenticated:
                try:
                    history = ScanHistory(
                        user_id=current_user.id,
                        scan_type='IP Intel',
                        target=result.get('cleaned_target') or query_input,
                        verdict=result.get('classification', 'Audited'),
                        risk_score=75 if result.get('risk_indicators') else 15,
                        details={
                            'ip': result.get('ip'),
                            'classification': result.get('classification'),
                            'country': result.get('geo_info', {}).get('country'),
                            'reverse_dns': result.get('reverse_dns')
                        }
                    )
                    db.session.add(history)
                    db.session.commit()
                except Exception:
                    db.session.rollback()

    return render_template('tools/ip_intel.html', result=result, query_input=query_input)
