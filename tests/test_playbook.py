import pytest
from app.services.playbook_data import OWASP_TOP_10, INCIDENT_RESPONSE_STEPS, CLI_CHEAT_SHEET

def test_playbook_data_structure():
    assert len(OWASP_TOP_10) >= 5
    assert all('vulnerable_code' in item and 'secure_code' in item for item in OWASP_TOP_10)
    assert len(INCIDENT_RESPONSE_STEPS) == 4
    assert len(CLI_CHEAT_SHEET) >= 4

def test_playbook_route(client):
    response = client.get('/playbook/')
    assert response.status_code == 200
    assert b'OWASP Top 10' in response.data
    assert b'Incident Response' in response.data
