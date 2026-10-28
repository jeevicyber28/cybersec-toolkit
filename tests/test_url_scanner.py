from app.services.ml_engine import extract_url_features, PhishingMLEngine

def test_feature_extraction():
    url = "http://paypal.com.verify-billing-status.xyz/auth/login?user=victim#step1"
    features, vector = extract_url_features(url)

    assert features['has_https'] == 0
    assert features['suspicious_tld'] == 1
    assert features['sensitive_keywords'] >= 2  # verify, login
    assert features['num_subdomains'] >= 2
    assert features['entropy'] > 3.0
    assert len(vector) == 16

def test_ml_prediction_and_explanations(app):
    model_path = app.config['MODEL_PATH']
    engine = PhishingMLEngine.get_instance(model_path)

    # Legitimate URL
    safe_res = engine.predict("https://www.google.com")
    assert safe_res['verdict'] == 'Safe'
    assert safe_res['risk_score'] < 35
    assert len(safe_res['top_contributions']) > 0

    # Phishing URL
    phish_res = engine.predict("http://192.168.1.100/paypal/login.php?cmd=verify")
    assert phish_res['verdict'] in ['Suspicious', 'Malicious']
    assert phish_res['risk_score'] >= 50
    assert any(c['feature'] in ['has_ip', 'has_https', 'sensitive_keywords'] for c in phish_res['top_contributions'])

def test_url_scanner_route(client):
    res = client.get('/url-scanner/')
    assert res.status_code == 200
    assert b'Explainable ML URL Phishing Detector' in res.data

    res = client.post('/url-scanner/', data={'url': 'https://en.wikipedia.org/wiki/Computer_security'}, follow_redirects=True)
    assert res.status_code == 200
    assert b'Verdict' in res.data
    assert b'Top Contributing Features' in res.data
