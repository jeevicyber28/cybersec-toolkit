import io

def test_api_docs_route(client):
    res = client.get('/api/docs')
    assert res.status_code == 200
    assert b'CyberSec Toolkit REST API Reference' in res.data

def test_api_scan_url(client):
    res = client.post('/api/v1/scan-url', json={
        'url': 'http://paypal.com.verify-account.xyz/login'
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'success'
    assert 'verdict' in data
    assert 'risk_score' in data
    assert len(data['top_contributions']) > 0

def test_api_scan_email(client):
    res = client.post('/api/v1/scan-email', json={
        'raw_email': 'From: admin@evil.com\nSubject: Account Alert\n\nClick: <a href="http://evil.com">https://chase.com</a>'
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'success'
    assert 'verdict' in data

def test_api_safety_score(client):
    res = client.get('/api/v1/safety-score')
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'success'
    assert 'safety_score' in data['metrics']
