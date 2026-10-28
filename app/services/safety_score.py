from datetime import datetime, timedelta, timezone
from app.models import ScanHistory, GameScore

def calculate_user_safety_metrics(user_id=None):
    """
    Computes overall safety score (0-100), donut chart distribution,
    and 7-day activity data for the user.
    """
    query = ScanHistory.query
    if user_id:
        query = query.filter_by(user_id=user_id)
    recent_scans = query.order_by(ScanHistory.created_at.desc()).limit(50).all()

    # Tool stats
    tool_counts = {'url': 0, 'email': 0, 'qr': 0, 'password': 0}
    verdict_counts = {'Safe': 0, 'Suspicious': 0, 'Malicious': 0}
    total_risk = 0.0

    for scan in recent_scans:
        t = scan.tool_type.lower()
        if t in tool_counts:
            tool_counts[t] += 1
        
        v = scan.verdict
        if 'Safe' in v or 'Strong' in v:
            verdict_counts['Safe'] += 1
        elif 'Suspicious' in v or 'Moderate' in v:
            verdict_counts['Suspicious'] += 1
        else:
            verdict_counts['Malicious'] += 1

        total_risk += scan.risk_score

    # Spot the Phish Game performance
    game_query = GameScore.query
    if user_id:
        game_query = game_query.filter_by(user_id=user_id)
    game_scores = game_query.order_by(GameScore.created_at.desc()).limit(10).all()

    quiz_accuracy = 85.0
    if game_scores:
        total_correct = sum(g.correct_answers for g in game_scores)
        total_rounds = sum(g.total_rounds for g in game_scores)
        if total_rounds > 0:
            quiz_accuracy = round((total_correct / total_rounds) * 100, 1)

    # Calculate overall Safety Score
    if recent_scans:
        avg_risk = total_risk / len(recent_scans)
        scan_safety = max(0.0, 100.0 - avg_risk)
        # 70% scan posture + 30% quiz awareness
        combined_score = round(0.7 * scan_safety + 0.3 * quiz_accuracy)
    else:
        # Default starting baseline
        combined_score = 82
        verdict_counts = {'Safe': 5, 'Suspicious': 2, 'Malicious': 1}

    # Weekly Activity (Last 7 days)
    now = datetime.now(timezone.utc)
    weekly_labels = []
    weekly_scans = []
    weekly_risks = []

    for i in range(6, -1, -1):
        day = now - timedelta(days=i)
        day_str = day.strftime('%a')
        weekly_labels.append(day_str)

        # Count scans on that day
        day_start = datetime(day.year, day.month, day.day, 0, 0, 0, tzinfo=timezone.utc)
        day_end = day_start + timedelta(days=1)
        
        day_scans = [s for s in recent_scans if s.created_at and day_start <= s.created_at.replace(tzinfo=timezone.utc if s.created_at.tzinfo is None else s.created_at.tzinfo) < day_end]
        count = len(day_scans)
        avg_day_safety = round(100.0 - (sum(s.risk_score for s in day_scans) / count)) if count > 0 else 85
        
        weekly_scans.append(count)
        weekly_risks.append(avg_day_safety)

    return {
        'safety_score': combined_score,
        'total_scans': len(recent_scans),
        'tool_counts': tool_counts,
        'verdict_counts': verdict_counts,
        'quiz_accuracy': quiz_accuracy,
        'weekly': {
            'labels': weekly_labels,
            'scans': weekly_scans,
            'safety_ratings': weekly_risks
        }
    }
