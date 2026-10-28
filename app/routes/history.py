import json
from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, jsonify, make_response, send_file
)
from flask_login import login_required, current_user
import io
from app import db
from app.models import ScanHistory
from app.services.pdf_generator import generate_history_pdf
from app.services.safety_score import calculate_user_safety_metrics

history_bp = Blueprint('history', __name__)

@history_bp.route('/')
@login_required
def index():
    tool_filter = request.args.get('tool', 'all').strip().lower()
    verdict_filter = request.args.get('verdict', 'all').strip()
    search_query = request.args.get('q', '').strip()

    query = ScanHistory.query.filter_by(user_id=current_user.id)

    if tool_filter and tool_filter != 'all':
        query = query.filter_by(tool_type=tool_filter)

    if verdict_filter and verdict_filter != 'all':
        query = query.filter(ScanHistory.verdict.ilike(f"%{verdict_filter}%"))

    if search_query:
        query = query.filter(ScanHistory.target.ilike(f"%{search_query}%"))

    scans = query.order_by(ScanHistory.created_at.desc()).all()

    return render_template(
        'history/index.html',
        scans=scans,
        tool_filter=tool_filter,
        verdict_filter=verdict_filter,
        search_query=search_query
    )

@history_bp.route('/delete/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan = ScanHistory.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    db.session.delete(scan)
    db.session.commit()
    flash('Scan record removed from history.', 'info')
    return redirect(url_for('history.index'))

@history_bp.route('/clear', methods=['POST'])
@login_required
def clear_all():
    ScanHistory.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    flash('All scan history records have been cleared.', 'info')
    return redirect(url_for('history.index'))

@history_bp.route('/export/json')
@login_required
def export_json():
    scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.created_at.desc()).all()
    data = [s.to_dict() for s in scans]
    
    response = make_response(json.dumps(data, indent=2))
    response.headers['Content-Disposition'] = f'attachment; filename=cybersec_audit_{current_user.username}.json'
    response.headers['Content-Type'] = 'application/json'
    return response

@history_bp.route('/export/pdf')
@login_required
def export_pdf():
    scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.created_at.desc()).all()
    scan_dicts = [s.to_dict() for s in scans]
    metrics = calculate_user_safety_metrics(current_user.id)
    
    pdf_bytes = generate_history_pdf(
        scans=scan_dicts,
        username=current_user.username,
        safety_score=metrics.get('safety_score', 85)
    )

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'cybersec_report_{current_user.username}.pdf'
    )
