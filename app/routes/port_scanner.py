from flask import Blueprint, render_template, request, flash
from flask_login import current_user
from app.services.port_scanner_service import audit_host_ports
from app.models import ScanHistory
from app import db

port_scanner_bp = Blueprint('port_scanner', __name__)

@port_scanner_bp.route('/', methods=['GET', 'POST'])
def index():
    result = None
    target_input = ''

    if request.method == 'POST':
        target_input = request.form.get('target', '').strip()
        if not target_input:
            flash('Please enter a valid hostname or IP address.', 'warning')
        else:
            result = audit_host_ports(target_input)

            if result.get('error'):
                flash(result['error'], 'danger')
            elif current_user.is_authenticated:
                try:
                    history = ScanHistory(
                        user_id=current_user.id,
                        scan_type='Port Audit',
                        target=result.get('hostname') or target_input,
                        verdict=f"{result.get('open_ports_count')} Open Ports",
                        risk_score=100 - result.get('hygiene_score', 100),
                        details={
                            'ip': result.get('ip'),
                            'open_ports': result.get('open_ports_count'),
                            'critical_findings': len(result.get('critical_findings', []))
                        }
                    )
                    db.session.add(history)
                    db.session.commit()
                except Exception:
                    db.session.rollback()

    return render_template('tools/port_scanner.html', result=result, target_input=target_input)
