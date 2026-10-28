import pytest
from app.services.port_scanner_service import audit_host_ports

def test_port_scanner_service():
    # Test on localhost
    result = audit_host_ports('127.0.0.1')
    assert result['ip'] == '127.0.0.1'
    assert result['total_scanned'] > 0
    assert 'ports' in result
    assert isinstance(result['ports'], list)
    assert 'hygiene_score' in result

def test_port_scanner_route(client):
    get_resp = client.get('/port-scanner/')
    assert get_resp.status_code == 200
    assert b'Network Port' in get_resp.data

    post_resp = client.post('/port-scanner/', data={'target': '127.0.0.1'}, follow_redirects=True)
    assert post_resp.status_code == 200
    assert b'Host Audited' in post_resp.data
