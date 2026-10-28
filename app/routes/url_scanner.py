import json
from flask import Blueprint, render_template, request, current_app, flash
from flask_login import current_user
from app import db
from app.models import ScanHistory
from app.services.ml_engine import PhishingMLEngine

url_scanner_bp = Blueprint('url_scanner', __name__)

@url_scanner_bp.route('/', methods=['GET', 'POST'])
def index():
    result = None
    url_input = ''

    if request.method == 'POST':
        url_input = request.form.get('url', '').strip()
        if not url_input:
            flash('Please enter a URL to analyze.', 'warning')
        else:
            model_path = current_app.config['MODEL_PATH']
            engine = PhishingMLEngine.get_instance(model_path)
            result = engine.predict(url_input)

            # Save scan record to history if user is authenticated
            if current_user.is_authenticated:
                history_entry = ScanHistory(
                    user_id=current_user.id,
                    tool_type='url',
                    target=url_input[:250],
                    verdict=result['verdict'],
                    risk_score=result['risk_score'],
                    details_json=json.dumps({
                        'top_contributions': result['top_contributions'],
                        'features': result['features']
                    })
                )
                db.session.add(history_entry)
                db.session.commit()

    return render_template('tools/url_scanner.html', result=result, url_input=url_input)
