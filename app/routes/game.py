import os
import json
import random
from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import current_user
from app import db
from app.models import GameScore

game_bp = Blueprint('game', __name__)

def load_all_game_items(path):
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return []
    return []

@game_bp.route('/')
def index():
    user_best = 0
    user_badge = 'Rookie'
    if current_user.is_authenticated:
        user_best = current_user.get_best_score()
        user_badge = current_user.get_badge()
    return render_template('tools/game.html', user_best=user_best, user_badge=user_badge)

@game_bp.route('/rounds', methods=['GET'])
def get_rounds():
    """Returns 10 randomized items for a new 10-round game session."""
    path = current_app.config['GAME_ITEMS_PATH']
    items = load_all_game_items(path)
    if not items:
        return jsonify({'error': 'Game items could not be loaded.'}), 500

    # Balance across categories and difficulties if possible
    selected = random.sample(items, min(10, len(items)))
    return jsonify({
        'rounds': selected,
        'total_rounds': len(selected)
    })

@game_bp.route('/submit', methods=['POST'])
def submit_score():
    data = request.get_json() or {}
    score = int(data.get('score', 0))
    max_streak = int(data.get('max_streak', 0))
    correct = int(data.get('correct_answers', 0))
    total = int(data.get('total_rounds', 10))

    # Determine badge
    if score >= 800:
        badge = 'Phish Hunter'
    elif score >= 500:
        badge = 'Defender'
    else:
        badge = 'Rookie'

    user_id = current_user.id if current_user.is_authenticated else None
    player_name = current_user.username if current_user.is_authenticated else 'Guest Agent'

    game_record = GameScore(
        user_id=user_id,
        player_name=player_name,
        score=score,
        max_streak=max_streak,
        badge=badge,
        rounds_completed=total,
        correct_answers=correct,
        total_rounds=total
    )
    db.session.add(game_record)
    db.session.commit()

    best_score = score
    if current_user.is_authenticated:
        best_score = current_user.get_best_score()

    return jsonify({
        'success': True,
        'badge': badge,
        'score': score,
        'best_score': best_score,
        'message': f"Great defense! You earned the '{badge}' badge."
    })
