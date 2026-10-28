from app.services.safety_score import calculate_user_safety_metrics
from app.models import ScanHistory
from app import db

def test_safety_score_calculation(app):
    with app.app_context():
        # Baseline without scans
        base_metrics = calculate_user_safety_metrics()
        assert 0 <= base_metrics['safety_score'] <= 100
        assert 'Safe' in base_metrics['verdict_counts']

        # Add mock scan entries
        s1 = ScanHistory(tool_type='url', target='https://google.com', verdict='Safe', risk_score=5.0)
        s2 = ScanHistory(tool_type='url', target='http://evil.com', verdict='Malicious', risk_score=95.0)
        db.session.add_all([s1, s2])
        db.session.commit()

        metrics = calculate_user_safety_metrics()
        assert metrics['total_scans'] == 2
        assert metrics['verdict_counts']['Safe'] >= 1
        assert metrics['verdict_counts']['Malicious'] >= 1
        assert len(metrics['weekly']['labels']) == 7
