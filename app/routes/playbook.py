from flask import Blueprint, render_template
from app.services.playbook_data import OWASP_TOP_10, INCIDENT_RESPONSE_STEPS, CLI_CHEAT_SHEET

playbook_bp = Blueprint('playbook', __name__)

@playbook_bp.route('/')
def index():
    return render_template(
        'tools/playbook.html',
        owasp_items=OWASP_TOP_10,
        ir_steps=INCIDENT_RESPONSE_STEPS,
        cli_tools=CLI_CHEAT_SHEET
    )
