import json
import os

def test_game_items_structure(app):
    items_path = app.config['GAME_ITEMS_PATH']
    assert os.path.exists(items_path)

    with open(items_path, 'r', encoding='utf-8') as f:
        items = json.load(f)

    # Must contain at least 40 items
    assert len(items) >= 40

    difficulties = set(i['difficulty'] for i in items)
    types = set(i['type'] for i in items)

    assert {'easy', 'medium', 'hard'}.issubset(difficulties)
    assert {'url', 'email', 'sms'}.issubset(types)

    for item in items:
        assert 'id' in item
        assert 'content' in item
        assert isinstance(item['is_phish'], bool)
        assert 'explanation' in item
        assert len(item['explanation']) > 10

def test_game_api_and_score_submission(client, auth_client):
    c, user_id = auth_client

    # Get rounds
    res = c.get('/game/rounds')
    assert res.status_code == 200
    data = res.get_json()
    assert len(data['rounds']) == 10

    # Submit score
    res = c.post('/game/submit', json={
        'score': 850,
        'max_streak': 6,
        'correct_answers': 9,
        'total_rounds': 10
      })
    assert res.status_code == 200
    sub_data = res.get_json()
    assert sub_data['badge'] == 'Phish Hunter'
    assert sub_data['best_score'] == 850
