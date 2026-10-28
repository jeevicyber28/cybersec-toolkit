import pytest
from app.services.ssl_headers_service import analyze_headers_and_ssl

def test_analyze_ssl_headers_service():
    # Test on a known public domain or mock
    result = analyze_headers_and_ssl('https://github.com')
    assert result['hostname'] == 'github.com'
    assert 'headers_audit' in result
    assert len(result['headers_audit']) >= 6
    assert 'score' in result
    assert result['grade'] in ['A+', 'A', 'B', 'C', 'D', 'F']

def test_ssl_headers_route(client):
    response = client.get('/ssl-headers/')
    assert response.status_code == 200
    assert b'Security Headers' in response.data

    post_resp = client.post('/ssl-headers/', data={'target': 'example.com'}, follow_redirects=True)
    assert post_resp.status_code == 200
    assert b'Inspected Target' in post_resp.data
