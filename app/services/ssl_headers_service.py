import socket
import ssl
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List

def analyze_headers_and_ssl(target: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Audits HTTP Security Headers and SSL/TLS certificate configurations.
    Returns scores, grades, certificate details, and actionable remediation tips.
    """
    # Normalize input
    target = target.strip()
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    parsed = urllib.parse.urlparse(target)
    hostname = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)

    results: Dict[str, Any] = {
        'target': target,
        'hostname': hostname,
        'port': port,
        'headers_audit': {},
        'ssl_info': {},
        'score': 100,
        'grade': 'A+',
        'warnings': [],
        'recommendations': [],
        'error': None
    }

    # 1. Inspect HTTP Security Headers
    try:
        req = urllib.request.Request(
            target,
            headers={'User-Agent': 'CyberSecToolkit-Auditor/2.0'}
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            results['raw_headers'] = dict(response.headers)
    except Exception as e:
        results['warnings'].append(f"HTTP request warning: {str(e)}")
        headers = {}
        results['raw_headers'] = {}

    # Define Security Header Checks
    security_checks = [
        {
            'key': 'content-security-policy',
            'name': 'Content-Security-Policy (CSP)',
            'importance': 'High',
            'points': 25,
            'desc': 'Mitigates Cross-Site Scripting (XSS) and data injection attacks.',
            'recommendation': "Add 'Content-Security-Policy' with a restrictive default-src policy."
        },
        {
            'key': 'strict-transport-security',
            'name': 'Strict-Transport-Security (HSTS)',
            'importance': 'High',
            'points': 20,
            'desc': 'Enforces secure HTTPS connections and prevents SSL stripping.',
            'recommendation': "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
        },
        {
            'key': 'x-content-type-options',
            'name': 'X-Content-Type-Options',
            'importance': 'Medium',
            'points': 15,
            'desc': 'Prevents MIME-type sniffing vulnerabilities.',
            'recommendation': "Set 'X-Content-Type-Options: nosniff'."
        },
        {
            'key': 'x-frame-options',
            'name': 'X-Frame-Options',
            'importance': 'Medium',
            'points': 15,
            'desc': 'Defends against Clickjacking by controlling iframe embedding.',
            'recommendation': "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
        },
        {
            'key': 'referrer-policy',
            'name': 'Referrer-Policy',
            'importance': 'Low',
            'points': 10,
            'desc': 'Controls how much referrer information is leaked in outgoing links.',
            'recommendation': "Set 'Referrer-Policy: strict-origin-when-cross-origin'."
        },
        {
            'key': 'permissions-policy',
            'name': 'Permissions-Policy',
            'importance': 'Low',
            'points': 10,
            'desc': 'Restricts browser hardware features (camera, microphone, geolocation).',
            'recommendation': "Configure 'Permissions-Policy' to disable unused sensitive APIs."
        }
    ]

    total_score = 0
    max_score = sum(c['points'] for c in security_checks)

    header_results = []
    for check in security_checks:
        val = headers.get(check['key'])
        passed = bool(val)
        if passed:
            total_score += check['points']
        else:
            results['recommendations'].append(check['recommendation'])

        header_results.append({
            'name': check['name'],
            'key': check['key'],
            'present': passed,
            'value': val or 'Missing',
            'importance': check['importance'],
            'desc': check['desc']
        })

    # Check for Information Leakage Headers
    leakage_headers = []
    for leak_key in ['server', 'x-powered-by', 'x-aspnet-version']:
        if leak_key in headers:
            leakage_headers.append(f"{leak_key}: {headers[leak_key]}")
            total_score = max(0, total_score - 5)
            results['warnings'].append(f"Information leakage: Server disclosed version info ({leak_key}: {headers[leak_key]})")

    results['headers_audit'] = header_results
    results['leakage_headers'] = leakage_headers

    # 2. SSL/TLS Certificate Audit
    ssl_info: Dict[str, Any] = {
        'active': False,
        'version': None,
        'cipher': None,
        'issuer': {},
        'subject': {},
        'valid_from': None,
        'valid_to': None,
        'days_remaining': None,
        'is_expired': False,
        'sans': []
    }

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()

                ssl_info['active'] = True
                ssl_info['version'] = tls_version
                ssl_info['cipher'] = cipher[0] if cipher else None

                # Extract Subject & Issuer
                if cert:
                    for item in cert.get('subject', ()):
                        for k, v in item:
                            ssl_info['subject'][k] = v
                    for item in cert.get('issuer', ()):
                        for k, v in item:
                            ssl_info['issuer'][k] = v

                    # Dates
                    not_before_str = cert.get('notBefore')
                    not_after_str = cert.get('notAfter')
                    if not_before_str and not_after_str:
                        # SSL date format: 'May 15 00:00:00 2026 GMT'
                        dt_before = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                        dt_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)

                        ssl_info['valid_from'] = dt_before.strftime('%Y-%m-%d %H:%M UTC')
                        ssl_info['valid_to'] = dt_after.strftime('%Y-%m-%d %H:%M UTC')
                        days_left = (dt_after - now).days
                        ssl_info['days_remaining'] = days_left

                        if days_left <= 0:
                            ssl_info['is_expired'] = True
                            results['warnings'].append("CRITICAL: SSL/TLS Certificate is EXPIRED!")
                            total_score = min(total_score, 30)
                        elif days_left < 15:
                            results['warnings'].append(f"WARNING: SSL Certificate expires in {days_left} days!")

                    # SANs
                    sans = [entry[1] for entry in cert.get('subjectAltName', ()) if entry[0] == 'DNS']
                    ssl_info['sans'] = sans[:10]  # Cap at 10 for clean UI
    except Exception as e:
        ssl_info['error'] = str(e)
        results['warnings'].append(f"SSL handshake error: {str(e)}")
        # Penalty if target was https but failed SSL
        if parsed.scheme == 'https':
            total_score = max(0, total_score - 30)

    results['ssl_info'] = ssl_info

    # Calculate Final Score and Grade
    scaled_score = int((total_score / max_score) * 100) if max_score > 0 else 50
    scaled_score = max(0, min(100, scaled_score))
    results['score'] = scaled_score

    if scaled_score >= 90:
        results['grade'] = 'A+'
        results['grade_class'] = 'success'
    elif scaled_score >= 80:
        results['grade'] = 'A'
        results['grade_class'] = 'success'
    elif scaled_score >= 70:
        results['grade'] = 'B'
        results['grade_class'] = 'info'
    elif scaled_score >= 55:
        results['grade'] = 'C'
        results['grade_class'] = 'warning'
    elif scaled_score >= 40:
        results['grade'] = 'D'
        results['grade_class'] = 'warning'
    else:
        results['grade'] = 'F'
        results['grade_class'] = 'danger'

    return results
