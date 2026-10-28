import math
import re
import requests

COMMON_PATTERNS = [
    (r'(?:123456|12345|1234567|12345678|123456789|987654321)', 'Sequential number series'),
    (r'(?:qwerty|asdfgh|zxcvbn|qwertz|azerty)', 'Keyboard row sequence (walk)'),
    (r'(.)\1{3,}', 'Repeated identical characters (4+)'),
    (r'(?:password|admin|welcome|letmein|monkey|dragon|master)', 'Common default or dictionary word'),
    (r'(?:19[5-9]\d|20[0-3]\d)', 'Year format (likely birth or event year)')
]

TOP_COMMON_PASSWORDS = {
    'password', '123456', '123456789', 'guest', 'qwerty', '12345678', '111111',
    '12345', '1234567', 'password1', '123123', 'admin', 'welcome', 'iloveyou',
    'pass123', 'letmein', 'monkey', 'dragon', 'master', 'football', 'secret'
}

def query_hibp_range(prefix_5):
    """
    K-Anonymity HIBP range query.
    Takes STRICTLY the first 5 hexadecimal characters of SHA-1 hash.
    Never accepts or logs plain passwords.
    """
    prefix = prefix_5.strip().upper()
    if not re.match(r'^[0-9A-F]{5}$', prefix):
        return False, "Invalid prefix. Must be exactly 5 hexadecimal characters."

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {
        'User-Agent': 'CyberSec-Toolkit-Defensive-Auditor'
    }

    try:
        resp = requests.get(url, headers=headers, timeout=6)
        if resp.status_code == 200:
            return True, resp.text
        return False, f"HIBP service returned HTTP {resp.status_code}"
    except Exception as e:
        return False, f"Could not reach HIBP API: {str(e)}"

def evaluate_password_strength(password):
    """Defensively evaluates entropy, patterns, and crack time."""
    if not password:
        return {
            'length': 0,
            'entropy_bits': 0,
            'score': 0,
            'rating': 'Very Weak',
            'rating_class': 'danger',
            'crack_time_offline': 'Instant',
            'crack_time_online': 'Instant',
            'patterns_found': [],
            'tips': ['Enter a password to evaluate.']
        }

    length = len(password)
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

    pool_size = 0
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_symbol: pool_size += 33

    # Shannon entropy calculation: L * log2(R)
    entropy_bits = round(length * math.log2(pool_size), 1) if pool_size > 0 else 0

    # Pattern check
    pwd_lower = password.lower()
    patterns_found = []
    if pwd_lower in TOP_COMMON_PASSWORDS:
        patterns_found.append('Matches known top breached dictionary password')

    for pattern, desc in COMMON_PATTERNS:
        if re.search(pattern, pwd_lower):
            patterns_found.append(desc)

    # Educational Tips
    tips = []
    if length < 12:
        tips.append('Increase length to at least 14-16 characters (length adds exponential entropy).')
    if not (has_lower and has_upper):
        tips.append('Mix both uppercase and lowercase letters.')
    if not has_digit:
        tips.append('Include numeric digits.')
    if not has_symbol:
        tips.append('Add non-alphanumeric special symbols (!, @, #, $, %, etc.).')
    if patterns_found:
        tips.append('Eliminate predictable sequences, years, and keyboard walks.')
    if not tips:
        tips.append('Excellent entropy! Consider using a passphrase of 4+ random words for superior memory retention.')

    # Score (0 to 100)
    score = min(100, int((entropy_bits / 85.0) * 100))
    if patterns_found:
        score = max(10, score - 25 * len(patterns_found))

    if score >= 80 and length >= 12:
        rating = 'Very Strong'
        rating_class = 'success'
    elif score >= 60 and length >= 10:
        rating = 'Strong'
        rating_class = 'primary'
    elif score >= 40:
        rating = 'Moderate'
        rating_class = 'warning'
    else:
        rating = 'Weak'
        rating_class = 'danger'

    # Crack time estimation
    total_combinations = pool_size ** length if pool_size > 0 else 0
    # 10 billion guesses/sec for high-end offline GPU rig
    offline_seconds = total_combinations / 10_000_000_000 if pool_size > 0 else 0
    # 100 guesses/sec for throttled online web service
    online_seconds = total_combinations / 100 if pool_size > 0 else 0

    def format_time(sec):
        if sec < 1: return 'Less than 1 second (Instant)'
        if sec < 60: return f'{int(sec)} seconds'
        if sec < 3600: return f'{int(sec // 60)} minutes'
        if sec < 86400: return f'{int(sec // 3600)} hours'
        if sec < 31536000: return f'{int(sec // 86400)} days'
        years = sec / 31536000
        if years < 1000: return f'{int(years)} years'
        if years < 1_000_000: return f'{int(years // 1000)} thousand years'
        return 'Millions of years'

    return {
        'length': length,
        'entropy_bits': entropy_bits,
        'score': score,
        'rating': rating,
        'rating_class': rating_class,
        'has_lower': has_lower,
        'has_upper': has_upper,
        'has_digit': has_digit,
        'has_symbol': has_symbol,
        'crack_time_offline': format_time(offline_seconds),
        'crack_time_online': format_time(online_seconds),
        'patterns_found': patterns_found,
        'tips': tips
    }
