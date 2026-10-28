import pytest

def test_new_rest_endpoints(client):
    # Hash Generate API
    h_gen = client.post('/api/v1/hash-generate', json={'text': 'cyber-defense-api'})
    assert h_gen.status_code == 200
    assert 'sha256' in h_gen.get_json()['hashes']

    # Hash Identify API
    h_id = client.post('/api/v1/hash-identify', json={'hash': '5d41402abc4b2a76b9719d911017c592'})
    assert h_id.status_code == 200
    assert any('MD5' in m['algorithm'] for m in h_id.get_json()['matches'])

    # Port Scan API
    p_scan = client.post('/api/v1/scan-ports', json={'host': '127.0.0.1'})
    assert p_scan.status_code == 200
    assert p_scan.get_json()['data']['ip'] == '127.0.0.1'

    # IP Intel API
    ip_res = client.post('/api/v1/scan-ip-intel', json={'query': '127.0.0.1'})
    assert ip_res.status_code == 200
    assert ip_res.get_json()['data']['is_loopback'] is True
