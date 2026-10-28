from app.models import User

def test_register_and_login(client, app):
    # Register new user
    res = client.post('/auth/register', data={
        'username': 'cybersec_pro',
        'email': 'pro@cybersec.test',
        'password': 'StrongPassword2026!',
        'confirm_password': 'StrongPassword2026!'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b'Account created successfully' in res.data

    with app.app_context():
        user = User.query.filter_by(username='cybersec_pro').first()
        assert user is not None
        assert user.check_password('StrongPassword2026!')
        assert len(user.api_key) >= 32

    # Logout
    res = client.get('/auth/logout', follow_redirects=True)
    assert res.status_code == 200
    assert b'logged out securely' in res.data

    # Login
    res = client.post('/auth/login', data={
        'identifier': 'cybersec_pro',
        'password': 'StrongPassword2026!'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b'Welcome back, cybersec_pro' in res.data

def test_register_validation(client):
    # Passwords do not match
    res = client.post('/auth/register', data={
        'username': 'failuser',
        'email': 'fail@cybersec.test',
        'password': 'Password123!',
        'confirm_password': 'DifferentPassword123!'
    }, follow_redirects=True)
    assert b'Passwords do not match' in res.data

    # Password too short
    res = client.post('/auth/register', data={
        'username': 'shortuser',
        'email': 'short@cybersec.test',
        'password': 'short',
        'confirm_password': 'short'
    }, follow_redirects=True)
    assert b'at least 8 characters' in res.data
