import pytest
import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
from app.config import TestConfig
from app.models import User, ScanHistory, GameScore

@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def auth_client(app, client):
    with app.app_context():
        user = User(username='testauditor', email='auditor@cybersec.test', password='SecurePassword123!')
        db.session.add(user)
        db.session.commit()
        user_id = user.id

    client.post('/auth/login', data={
        'identifier': 'testauditor',
        'password': 'SecurePassword123!'
    }, follow_redirects=True)

    return client, user_id
