"""
Cyber Defense Playbook, OWASP Top 10 Reference, and Incident Response Guide.
Provides rich, educational reference material for security engineers and developers.
"""

OWASP_TOP_10 = [
    {
        'id': 'A01:2021',
        'title': 'Broken Access Control',
        'badge': 'Critical',
        'badge_class': 'danger',
        'desc': 'Flaws permitting users to act outside of their intended permissions, such as accessing sensitive user records by altering URL parameters (IDOR).',
        'vulnerable_code': """# Vulnerable: Insecure Direct Object Reference (IDOR)
@app.route('/user/profile/<int:user_id>')
def view_profile(user_id):
    # Missing authorization check! Any user can query any profile!
    user = User.query.get(user_id)
    return jsonify(user.to_dict())""",
        'secure_code': """# Remediated: Enforced Principal Authentication & Ownership
@app.route('/user/profile')
@login_required
def view_profile():
    # Only loads the session-authenticated user's profile
    return jsonify(current_user.to_dict())""",
        'prevention': [
            'Deny by default: Ensure all endpoints require explicit permissions unless declared public.',
            'Implement centralized access control mechanisms and verify user ownership on server-side.',
            'Disable web server directory listing and enforce metadata protection.'
        ]
    },
    {
        'id': 'A02:2021',
        'title': 'Cryptographic Failures',
        'badge': 'High',
        'badge_class': 'danger',
        'desc': 'Previously known as Sensitive Data Exposure. Occurs when passwords, tokens, or PII are transmitted in cleartext or hashed using obsolete algorithms like MD5 or SHA-1.',
        'vulnerable_code': """# Vulnerable: Insecure fast hashing without salt or work factor
import hashlib

def store_password(password):
    # MD5 can be reversed in seconds using GPU rainbow tables!
    return hashlib.md5(password.encode()).hexdigest()""",
        'secure_code': """# Remediated: Adaptive Memory-Hard Argon2id / Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash

def store_password(password):
    # Salted, compute-hard, and immune to GPU rainbow tables
    return generate_password_hash(password, method='scrypt')""",
        'prevention': [
            'Classify data processed, stored, or transmitted by an application and encrypt at rest with AES-GCM.',
            'Never use MD5, SHA-1, RC4, or DES for cryptographic protection.',
            'Enforce TLS 1.3 with HSTS (HTTP Strict Transport Security).'
        ]
    },
    {
        'id': 'A03:2021',
        'title': 'Injection (SQLi & Command Injection)',
        'badge': 'Critical',
        'badge_class': 'danger',
        'desc': 'Hostile data sent to an interpreter as part of a command or query tricks the interpreter into executing unintended commands or accessing unauthorized data.',
        'vulnerable_code': """# Vulnerable: String concatenation in SQL Query
@app.route('/search')
def search():
    query = request.args.get('q')
    # Attacker injects: ' OR 1=1; --
    sql = f"SELECT * FROM items WHERE name = '{query}'"
    return db.engine.execute(sql)""",
        'secure_code': """# Remediated: Parameterized Query / ORM Binding
@app.route('/search')
def search():
    query = request.args.get('q')
    # Values are strictly bound as data, never parsed as executable SQL
    items = Item.query.filter(Item.name.ilike(f"%{query}%")).all()
    return jsonify([i.to_dict() for i in items])""",
        'prevention': [
            'Use parameterized queries, prepared statements, or modern ORMs everywhere.',
            'Implement positive server-side input validation and escape special characters.',
            'Enforce least-privilege database user permissions (e.g. read-only where possible).'
        ]
    },
    {
        'id': 'A05:2021',
        'title': 'Security Misconfiguration',
        'badge': 'High',
        'badge_class': 'warning',
        'desc': 'Unpatched flaws, default accounts, unused pages, unhardened cloud storage, and overly permissive HTTP headers.',
        'vulnerable_code': """# Vulnerable: Debug mode enabled in production
app = Flask(__name__)
# EXTREME RISK: Interactive Werkzeug debugger allows arbitrary Python execution!
app.run(host='0.0.0.0', port=5000, debug=True)""",
        'secure_code': """# Remediated: Hardened production WSGI deployment
import os
from app import create_app

app = create_app()
# Production: Debug always False, served via Gunicorn / Nginx
if __name__ == '__main__':
    is_debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='127.0.0.1', port=5000, debug=is_debug)""",
        'prevention': [
            'Disable development debugging and stack traces in production.',
            'Apply secure HTTP response headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).',
            'Remove unnecessary features, components, and default accounts.'
        ]
    },
    {
        'id': 'A10:2021',
        'title': 'Server-Side Request Forgery (SSRF)',
        'badge': 'High',
        'badge_class': 'danger',
        'desc': 'Web application fetches a remote resource without validating the user-supplied URL, allowing attackers to coerce the server into scanning internal network services or reading cloud instance metadata (e.g., AWS 169.254.169.254).',
        'vulnerable_code': """# Vulnerable: Unrestricted server-side HTTP request
@app.route('/fetch-avatar')
def fetch_avatar():
    url = request.args.get('url')
    # Attacker targets: http://169.254.169.254/latest/meta-data/iam/
    return requests.get(url).content""",
        'secure_code': """# Remediated: IP Allowlisting & Private Range Blocking
import ipaddress, socket, urllib.parse

def is_safe_destination(url):
    host = urllib.parse.urlparse(url).hostname
    ip = socket.gethostbyname(host)
    ip_obj = ipaddress.ip_address(ip)
    # Block internal, loopback, link-local, and cloud metadata ranges!
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        raise ValueError("SSRF Alert: Request to private/internal IP blocked.")
    return True""",
        'prevention': [
            'Sanitize and filter all client-supplied input URLs against an allowlist of permitted protocols and domains.',
            'Block requests to RFC 1918 private subnets and link-local cloud metadata endpoints (169.254.169.254).',
            'Disable HTTP redirections in server-side HTTP clients.'
        ]
    }
]

INCIDENT_RESPONSE_STEPS = [
    {
        'phase': 'Phase 1: Identification & Triage',
        'icon': '🔍',
        'desc': 'Detect anomalous alerts, verify IOCs (Indicators of Compromise), and classify severity.',
        'checklist': [
            'Isolate alerted host from the primary network segment (quarantine VLAN).',
            'Verify alert fidelity and rule out false positives.',
            'Document timeline and establish chain of custody for volatile logs.'
        ]
    },
    {
        'phase': 'Phase 2: Containment',
        'icon': '🛡️',
        'desc': 'Prevent lateral movement, command-and-control communication, and ongoing data exfiltration.',
        'checklist': [
            'Revoke compromised API tokens, session cookies, and credentials.',
            'Apply emergency firewall rules blocking C2 IP addresses and malicious domains.',
            'Capture volatile memory (RAM) dump and disk image before rebooting.'
        ]
    },
    {
        'phase': 'Phase 3: Eradication & Recovery',
        'icon': '🧹',
        'desc': 'Remove rootkits, backdoors, unauthorized scheduled tasks, and restore clean systems.',
        'checklist': [
            'Re-image compromised systems from known-good golden images.',
            'Patch the initial exploitation vector (CVE/vulnerability/misconfiguration).',
            'Conduct comprehensive vulnerability scan before re-introducing system to production.'
        ]
    },
    {
        'phase': 'Phase 4: Post-Incident Review',
        'icon': '📝',
        'desc': 'Analyze root cause, update runbooks, and enhance detection capabilities.',
        'checklist': [
            'Draft detailed incident post-mortem with root-cause analysis.',
            'Update detection rules and SIEM correlation queries.',
            'Conduct tabletop simulation to test lessons learned.'
        ]
    }
]

CLI_CHEAT_SHEET = [
    {
        'tool': 'OpenSSL',
        'command': 'openssl s_client -connect example.com:443 -servername example.com',
        'purpose': 'Inspect live SSL/TLS certificate chain, handshake details, and cipher suites.'
    },
    {
        'tool': 'cURL',
        'command': 'curl -I -s https://example.com | grep -iE "strict|content-security|x-frame|x-content"',
        'purpose': 'Rapidly extract defensive HTTP security headers from any endpoint.'
    },
    {
        'tool': 'Dig (DNS)',
        'command': 'dig +short TXT _dmarc.example.com',
        'purpose': 'Query and verify DMARC policy deployment for email anti-spoofing protection.'
    },
    {
        'tool': 'Sha256sum',
        'command': 'sha256sum -c SHA256SUMS.txt',
        'purpose': 'Validate cryptographic checksums across downloaded packages against supplier hashes.'
    },
    {
        'tool': 'TCPDump',
        'command': 'tcpdump -nnvv -i eth0 port 53 or port 80',
        'purpose': 'Capture live packet traces on DNS and HTTP traffic for intrusion forensics.'
    }
]
