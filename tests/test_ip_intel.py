import pytest
from app.services.ip_intel_service import analyze_ip_and_domain

def test_ip_intel_service():
    # Loopback IP
    res_loopback = analyze_ip_and_domain('127.0.0.1')
    assert res_loopback['is_loopback'] is True
    assert res_loopback['ip'] == '127.0.0.1'

    # Domain / hostname
    res_domain = analyze_ip_and_domain('localhost')
    assert res_domain['is_ip_address'] is False
    assert res_domain['ip'] is not None

def test_ip_intel_route(client):
    get_resp = client.get('/ip-intel/')
    assert get_resp.status_code == 200
    assert b'Threat Intelligence' in get_resp.data

    post_resp = client.post('/ip-intel/', data={'query': '127.0.0.1'}, follow_redirects=True)
    assert post_resp.status_code == 200
    assert b'Reverse DNS' in post_resp.data
