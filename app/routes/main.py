import os
import json
from flask import Blueprint, render_template, current_app
from flask_login import current_user
from app.services.safety_score import calculate_user_safety_metrics

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/dashboard')
def dashboard():
    user_id = current_user.id if current_user.is_authenticated else None
    metrics = calculate_user_safety_metrics(user_id)
    return render_template('dashboard.html', metrics=metrics)

@main_bp.route('/model-info')
def model_info():
    metrics_path = current_app.config['METRICS_PATH']
    metrics_data = {}
    if os.path.exists(metrics_path):
        try:
            with open(metrics_path, 'r', encoding='utf-8') as f:
                metrics_data = json.load(f)
        except Exception:
            metrics_data = {}
    return render_template('tools/model_info.html', metrics=metrics_data)
