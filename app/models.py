import secrets
from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    api_key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    scans = db.relationship('ScanHistory', backref='author', lazy='dynamic', cascade='all, delete-orphan')
    game_scores = db.relationship('GameScore', backref='player', lazy='dynamic', cascade='all, delete-orphan')

    def __init__(self, username, email, password=None):
        self.username = username.strip()
        self.email = email.strip().lower()
        if password:
            self.set_password(password)
        self.api_key = secrets.token_hex(24)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def regenerate_api_key(self):
        self.api_key = secrets.token_hex(24)
        return self.api_key

    def get_best_score(self):
        best = self.game_scores.order_by(GameScore.score.desc()).first()
        return best.score if best else 0

    def get_badge(self):
        best_score = self.get_best_score()
        if best_score >= 800:
            return 'Phish Hunter'
        elif best_score >= 500:
            return 'Defender'
        return 'Rookie'

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'api_key': self.api_key,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'best_score': self.get_best_score(),
            'badge': self.get_badge()
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class ScanHistory(db.Model):
    __tablename__ = 'scan_history'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    tool_type = db.Column(db.String(32), nullable=False, index=True)  # 'url', 'email', 'qr', 'password'
    target = db.Column(db.String(256), nullable=False)
    verdict = db.Column(db.String(32), nullable=False)  # 'Safe', 'Suspicious', 'Malicious'
    risk_score = db.Column(db.Float, nullable=False, default=0.0)  # 0 to 100
    details_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'tool_type': self.tool_type,
            'target': self.target,
            'verdict': self.verdict,
            'risk_score': round(self.risk_score, 1),
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else ''
        }


class GameScore(db.Model):
    __tablename__ = 'game_scores'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    player_name = db.Column(db.String(64), nullable=False, default='Anonymous')
    score = db.Column(db.Integer, nullable=False, default=0)
    max_streak = db.Column(db.Integer, nullable=False, default=0)
    badge = db.Column(db.String(32), nullable=False, default='Rookie')
    rounds_completed = db.Column(db.Integer, nullable=False, default=10)
    correct_answers = db.Column(db.Integer, nullable=False, default=0)
    total_rounds = db.Column(db.Integer, nullable=False, default=10)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'player_name': self.player_name,
            'score': self.score,
            'max_streak': self.max_streak,
            'badge': self.badge,
            'correct_answers': self.correct_answers,
            'total_rounds': self.total_rounds,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else ''
        }
