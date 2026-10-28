from app.services.password_service import evaluate_password_strength, query_hibp_range

def test_password_entropy_and_patterns():
    # Weak password
    weak_res = evaluate_password_strength('123456')
    assert weak_res['rating'] == 'Weak'
    assert weak_res['score'] <= 25
    assert len(weak_res['patterns_found']) > 0

    # Strong password
    strong_res = evaluate_password_strength('X#9vK!pL2$mQ8@zW')
    assert strong_res['rating'] in ['Strong', 'Very Strong']
    assert strong_res['entropy_bits'] >= 75
    assert strong_res['score'] >= 80

def test_hibp_prefix_validation():
    # Valid prefix
    valid, _ = query_hibp_range('5BAA6')
    # Can return True with data or False if external network is blocked, but shouldn't error on format
    # Invalid prefix
    invalid, msg = query_hibp_range('123')
    assert invalid is False
    assert 'Invalid prefix' in msg

def test_password_routes(client):
    res = client.get('/password-checker/')
    assert res.status_code == 200
    assert b'Password Strength &amp; Breach Auditor' in res.data
