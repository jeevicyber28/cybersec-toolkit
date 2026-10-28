import os
import re
import math
import joblib
import numpy as np
from urllib.parse import urlparse

FEATURE_NAMES = [
    'url_length',
    'domain_length',
    'dot_count',
    'hyphen_count',
    'at_count',
    'question_count',
    'equal_count',
    'slash_count',
    'digit_count',
    'has_ip',
    'has_https',
    'num_subdomains',
    'suspicious_tld',
    'sensitive_keywords',
    'entropy',
    'is_shortened'
]

FEATURE_LABELS = {
    'url_length': 'Overall URL Length',
    'domain_length': 'Hostname Length',
    'dot_count': 'Period / Dot Count',
    'hyphen_count': 'Hyphen Count',
    'at_count': '@ Sign Presence (Credential masking)',
    'question_count': 'Query Parameter Count',
    'equal_count': 'Key-Value Assignment Count',
    'slash_count': 'Directory Depth (Slash Count)',
    'digit_count': 'Total Digits Count',
    'has_ip': 'Raw IP Address in Hostname',
    'has_https': 'HTTPS Protocol Implementation',
    'num_subdomains': 'Subdomain Level Count',
    'suspicious_tld': 'High-Risk / Suspicious TLD',
    'sensitive_keywords': 'Brand / Phishing Lure Keywords',
    'entropy': 'URL Character Shannon Entropy',
    'is_shortened': 'URL Shortener Redirection'
}

SUSPICIOUS_TLDS = {
    'xyz', 'top', 'club', 'work', 'info', 'live', 'cc', 'fit', 'tk', 'gq',
    'ml', 'cf', 'ga', 'buzz', 'rest', 'stream', 'download', 'win', 'bid',
    'loan', 'click', 'link'
}

SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bit.do', 'cutt.ly', 'rb.gy', 'shorte.st'
}

SENSITIVE_WORDS = [
    'login', 'signin', 'verify', 'verification', 'update', 'banking', 'secure',
    'account', 'wallet', 'paypal', 'apple', 'security', 'billing', 'confirm',
    'support', 'recover', 'passcode', 'credential', 'auth', 'alert'
]

def calculate_entropy(text):
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    char_counts = {}
    for c in text:
        char_counts[c] = char_counts.get(c, 0) + 1
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def is_ip_address(domain):
    # Check IPv4
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, domain):
        parts = domain.split('.')
        return int(all(0 <= int(p) <= 255 for p in parts))
    return 0

def extract_url_features(url):
    """Extract 16 defensive and ML-friendly features from a given URL."""
    url = (url or '').strip()
    if not url.startswith(('http://', 'https://')):
        url_with_scheme = 'http://' + url
    else:
        url_with_scheme = url

    parsed = urlparse(url_with_scheme)
    domain = parsed.netloc.lower().split(':')[0]
    path = parsed.path
    query = parsed.query

    # Subdomains count
    parts = domain.split('.')
    num_subdomains = max(0, len(parts) - 2) if len(parts) >= 2 else 0

    # TLD
    tld = parts[-1] if len(parts) > 1 else ''
    suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # Shortener check
    is_shortened = 1 if domain in SHORTENERS else 0

    # IP check
    has_ip = is_ip_address(domain)

    # Keywords count
    url_lower = url.lower()
    keyword_hits = sum(1 for kw in SENSITIVE_WORDS if kw in url_lower)

    features = {
        'url_length': len(url),
        'domain_length': len(domain),
        'dot_count': url.count('.'),
        'hyphen_count': url.count('-'),
        'at_count': url.count('@'),
        'question_count': url.count('?'),
        'equal_count': url.count('='),
        'slash_count': url.count('/'),
        'digit_count': sum(c.isdigit() for c in url),
        'has_ip': has_ip,
        'has_https': 1 if parsed.scheme == 'https' else 0,
        'num_subdomains': num_subdomains,
        'suspicious_tld': suspicious_tld,
        'sensitive_keywords': keyword_hits,
        'entropy': calculate_entropy(url),
        'is_shortened': is_shortened
    }

    feature_vector = [features[k] for k in FEATURE_NAMES]
    return features, feature_vector


class PhishingMLEngine:
    _instance = None

    def __init__(self, model_path=None):
        self.model = None
        self.feature_importances = None
        self.load_model(model_path)

    @classmethod
    def get_instance(cls, model_path=None):
        if cls._instance is None:
            cls._instance = PhishingMLEngine(model_path)
        return cls._instance

    def load_model(self, model_path=None):
        if model_path and os.path.exists(model_path):
            try:
                bundle = joblib.load(model_path)
                if isinstance(bundle, dict):
                    self.model = bundle.get('model')
                    self.feature_importances = bundle.get('feature_importances')
                else:
                    self.model = bundle
                    self.feature_importances = getattr(bundle, 'feature_importances_', None)
            except Exception as e:
                print(f"Warning: Could not load model from {model_path}: {e}")
                self.model = None

    def predict(self, url):
        features, vector = extract_url_features(url)
        
        # Rule-based / fallback baseline calculation
        heuristic_score = 0
        if features['has_ip']: heuristic_score += 35
        if features['at_count'] > 0: heuristic_score += 30
        if features['suspicious_tld']: heuristic_score += 25
        if features['sensitive_keywords'] >= 2: heuristic_score += 25
        elif features['sensitive_keywords'] == 1: heuristic_score += 15
        if features['num_subdomains'] >= 3: heuristic_score += 20
        if features['is_shortened']: heuristic_score += 15
        if features['hyphen_count'] >= 3: heuristic_score += 15
        if features['entropy'] > 4.6: heuristic_score += 15
        if not features['has_https']: heuristic_score += 10
        if features['url_length'] > 90: heuristic_score += 10

        heuristic_prob = min(max(heuristic_score / 100.0, 0.02), 0.98)

        if self.model is not None:
            try:
                X = np.array([vector])
                probs = self.model.predict_proba(X)[0]
                phish_prob = float(probs[1])
                # Ensemble blend with domain heuristics for edge cases
                final_prob = 0.75 * phish_prob + 0.25 * heuristic_prob
            except Exception:
                final_prob = heuristic_prob
        else:
            final_prob = heuristic_prob

        risk_score = round(final_prob * 100, 1)
        if risk_score >= 65:
            verdict = 'Malicious'
            verdict_class = 'danger'
        elif risk_score >= 35:
            verdict = 'Suspicious'
            verdict_class = 'warning'
        else:
            verdict = 'Safe'
            verdict_class = 'success'

        # Explainable ML: Calculate top contributing features
        explanations = self._explain_prediction(features, vector, final_prob)

        return {
            'url': url,
            'verdict': verdict,
            'verdict_class': verdict_class,
            'risk_score': risk_score,
            'phishing_probability': round(final_prob, 3),
            'features': features,
            'feature_labels': FEATURE_LABELS,
            'top_contributions': explanations
        }

    def _explain_prediction(self, features, vector, prob):
        """Explainable ML: compute feature weights and directional impact."""
        # Baseline reference centers for legitimate URLs
        baseline = {
            'url_length': 32.0,
            'domain_length': 14.0,
            'dot_count': 2.0,
            'hyphen_count': 0.0,
            'at_count': 0.0,
            'question_count': 0.0,
            'equal_count': 0.0,
            'slash_count': 2.0,
            'digit_count': 0.0,
            'has_ip': 0.0,
            'has_https': 1.0,
            'num_subdomains': 0.0,
            'suspicious_tld': 0.0,
            'sensitive_keywords': 0.0,
            'entropy': 3.6,
            'is_shortened': 0.0
        }

        # Weights if model features available or standard importance
        weights = {
            'has_ip': 0.16,
            'at_count': 0.14,
            'suspicious_tld': 0.13,
            'sensitive_keywords': 0.12,
            'num_subdomains': 0.09,
            'entropy': 0.08,
            'is_shortened': 0.07,
            'has_https': 0.06,
            'hyphen_count': 0.05,
            'dot_count': 0.04,
            'url_length': 0.03,
            'digit_count': 0.02,
            'domain_length': 0.02,
            'slash_count': 0.01,
            'question_count': 0.01,
            'equal_count': 0.01
        }

        if self.feature_importances is not None and len(self.feature_importances) == len(FEATURE_NAMES):
            for i, name in enumerate(FEATURE_NAMES):
                weights[name] = float(self.feature_importances[i])

        contributions = []
        for name in FEATURE_NAMES:
            val = features[name]
            base = baseline[name]
            w = weights.get(name, 0.05)

            # Impact calculation
            if name == 'has_https':
                # Missing HTTPS increases risk
                diff = (1.0 - val)
            else:
                diff = max(0.0, val - base)
                # Normalize length / digits / entropy
                if name in ['url_length', 'domain_length', 'digit_count']:
                    diff = min(diff / 30.0, 3.0)
                elif name == 'entropy':
                    diff = min(diff / 1.5, 2.0)

            score_impact = diff * w * 100.0

            if score_impact > 0.5:
                direction = 'increases_risk'
            elif score_impact == 0 and name == 'has_https' and val == 1:
                direction = 'reduces_risk'
                score_impact = 10.0
            else:
                direction = 'neutral'

            contributions.append({
                'feature': name,
                'label': FEATURE_LABELS[name],
                'value': val,
                'weight': round(w * 100, 1),
                'impact': round(score_impact, 1),
                'direction': direction
            })

        # Sort by impact descending and take top 6
        contributions.sort(key=lambda x: x['impact'], reverse=True)
        return contributions[:6]
