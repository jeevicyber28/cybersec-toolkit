import re
import email
from email.utils import parseaddr, parsedate_to_datetime
from urllib.parse import urlparse

RISKY_ATTACHMENT_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.jar',
    '.iso', '.img', '.dmg', '.docm', '.xlsm', '.pptm', '.vbe', '.wsf',
    '.com', '.pif'
}

URGENCY_PATTERNS = [
    (r'\b(account.*(?:suspend|deactivat|terminat|lock|restrict))\b', 'Account suspension or lockout threat', 20),
    (r'\b(within\s+\d+\s*(?:hours?|days?|mins?)|immediate(?:ly)?|urgent(?:ly)?|action required)\b', 'Artificially urgent deadline', 15),
    (r'\b(unauthorized\s+(?:access|activity|charge|transaction)|security\s+alert)\b', 'Fabricated security breach or alert', 15),
    (r'\b(wire\s+transfer|gift\s+cards?|bitcoin|crypto|western\s+union)\b', 'Unusual or untraceable payment demand', 25),
    (r'\b(verify\s+your\s+identity|confirm\s+your\s+credentials|update\s+billing)\b', 'Credential or billing harvesting lure', 20),
    (r'\b(failure\s+to\s+respond|legal\s+action|law\s+enforcement|arrest)\b', 'Intimidation and coercive pressure', 25)
]

def extract_domain(email_address):
    if not email_address:
        return ''
    email_clean = parseaddr(email_address)[1]
    if '@' in email_clean:
        return email_clean.split('@')[-1].lower().strip('>').strip()
    return ''

def parse_auth_results(headers_text):
    auth_data = {
        'spf': {'status': 'Unknown', 'details': 'No SPF record found in headers'},
        'dkim': {'status': 'Unknown', 'details': 'No DKIM result found in headers'},
        'dmarc': {'status': 'Unknown', 'details': 'No DMARC result found in headers'}
    }

    # Search Authentication-Results and Received-SPF
    auth_lines = re.findall(r'(?:Authentication-Results|Received-SPF):\s*([^\r\n]+(?:\r?\n\s+[^\r\n]+)*)', headers_text, re.IGNORECASE)
    combined_auth = ' '.join(auth_lines).lower()

    # SPF match
    spf_match = re.search(r'\bspf=(\w+)', combined_auth)
    if not spf_match:
        spf_rec = re.search(r'received-spf:\s*(\w+)', headers_text, re.IGNORECASE)
        if spf_rec:
            status = spf_rec.group(1).capitalize()
            auth_data['spf'] = {'status': status, 'details': f'Received-SPF reported {status}'}
    else:
        status = spf_match.group(1).capitalize()
        auth_data['spf'] = {'status': status, 'details': f'Authentication-Results reported SPF {status}'}

    # DKIM match
    dkim_match = re.search(r'\bdkim=(\w+)', combined_auth)
    if dkim_match:
        status = dkim_match.group(1).capitalize()
        auth_data['dkim'] = {'status': status, 'details': f'Authentication-Results reported DKIM {status}'}

    # DMARC match
    dmarc_match = re.search(r'\bdmarc=(\w+)', combined_auth)
    if dmarc_match:
        status = dmarc_match.group(1).capitalize()
        auth_data['dmarc'] = {'status': status, 'details': f'Authentication-Results reported DMARC {status}'}

    return auth_data

def parse_received_hops(msg):
    received_headers = msg.get_all('received', [])
    if not received_headers:
        return []

    # Reverse to read chronological journey from origin (sender) to destination (recipient's MX)
    chronological_hops = list(reversed(received_headers))
    hops = []
    prev_dt = None

    for i, raw_hop in enumerate(chronological_hops, 1):
        hop_clean = ' '.join(raw_hop.split())
        
        # Extract IP and hosts
        ip_match = re.search(r'\[([0-9a-fA-F:\.]+)\]', hop_clean)
        ip = ip_match.group(1) if ip_match else 'Unknown IP'

        from_match = re.search(r'from\s+([^\s;]+)', hop_clean, re.IGNORECASE)
        from_host = from_match.group(1) if from_match else 'Unknown sender'

        by_match = re.search(r'by\s+([^\s;]+)', hop_clean, re.IGNORECASE)
        by_host = by_match.group(1) if by_match else 'Unknown receiver'

        # Timestamp is usually after semicolon ';'
        parts = raw_hop.rsplit(';', 1)
        timestamp_str = 'Unknown time'
        dt = None
        delay_seconds = None

        if len(parts) == 2:
            raw_time = parts[1].strip()
            try:
                dt = parsedate_to_datetime(raw_time)
                timestamp_str = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                if prev_dt and dt >= prev_dt:
                    delay_seconds = int((dt - prev_dt).total_seconds())
                prev_dt = dt
            except Exception:
                timestamp_str = raw_time[:35]

        hops.append({
            'hop_number': i,
            'from_host': from_host,
            'by_host': by_host,
            'ip': ip,
            'timestamp': timestamp_str,
            'delay_seconds': delay_seconds,
            'raw': hop_clean[:180] + ('...' if len(hop_clean) > 180 else '')
        })

    return hops

def find_link_mismatches(text):
    """Detect links where visible text claims one domain while href goes to another."""
    mismatches = []
    
    # HTML link pattern
    html_links = re.findall(r'<a\s+[^>]*?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', text, re.IGNORECASE | re.DOTALL)
    for href, display in html_links:
        display_clean = re.sub(r'<[^>]+>', '', display).strip()
        # Check if display text contains a domain like example.com or http://
        domain_like = re.search(r'(?:https?:\/\/)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', display_clean)
        if domain_like:
            shown_domain = domain_like.group(1).lower()
            try:
                actual_parsed = urlparse(href if '://' in href else 'http://' + href)
                actual_domain = actual_parsed.netloc.lower().split(':')[0]
                
                # Check mismatch
                if shown_domain and actual_domain and shown_domain != actual_domain:
                    # Ignore minor subdomain matching
                    if not actual_domain.endswith('.' + shown_domain) and not shown_domain.endswith('.' + actual_domain):
                        mismatches.append({
                            'display_text': display_clean,
                            'shown_domain': shown_domain,
                            'actual_url': href,
                            'actual_domain': actual_domain,
                            'risk': 'Critical Deception (Display text spoofs reputable domain)'
                        })
            except Exception:
                pass

    return mismatches

def find_risky_attachments(headers_text, body_text):
    found = []
    seen = set()
    combined = headers_text + ' ' + body_text
    
    # 1. Search filename="..." patterns in MIME headers or body
    filename_matches = re.findall(r'filename=["\']?([^"\';\r\n]+)["\']?', combined, re.IGNORECASE)
    for fn in filename_matches:
        fn_clean = fn.strip()
        for ext in RISKY_ATTACHMENT_EXTENSIONS:
            if fn_clean.lower().endswith(ext) and fn_clean.lower() not in seen:
                seen.add(fn_clean.lower())
                found.append({
                    'filename': fn_clean,
                    'extension': ext,
                    'risk': f'High Risk Executable/Script Extension ({ext})'
                })
                break

    # 2. Search direct filename references with risky extensions (e.g. payload.zip.exe or test.scr)
    raw_file_matches = re.findall(r'\b([\w.-]+\.(?:' + '|'.join(e.lstrip('.') for e in RISKY_ATTACHMENT_EXTENSIONS) + r'))\b', combined, re.IGNORECASE)
    for fn in raw_file_matches:
        fn_clean = fn.strip()
        for ext in RISKY_ATTACHMENT_EXTENSIONS:
            if fn_clean.lower().endswith(ext) and fn_clean.lower() not in seen:
                seen.add(fn_clean.lower())
                found.append({
                    'filename': fn_clean,
                    'extension': ext,
                    'risk': f'High Risk Executable/Script Extension ({ext})'
                })
                break

    return found

def analyze_urgency_language(text):
    findings = []
    score_addition = 0
    for pattern, description, weight in URGENCY_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            findings.append({
                'category': description,
                'sample': matches[0] if isinstance(matches[0], str) else matches[0][0],
                'weight': weight
            })
            score_addition += weight
    return findings, min(score_addition, 40)


def analyze_email(raw_content):
    """Comprehensive defensive analysis of raw email headers and body."""
    raw_content = raw_content or ''
    msg = email.message_from_string(raw_content)

    from_header = msg.get('from', '')
    reply_to = msg.get('reply-to', '')
    return_path = msg.get('return-path', '')
    subject = msg.get('subject', '(No Subject)')
    date_header = msg.get('date', '')

    from_domain = extract_domain(from_header)
    reply_to_domain = extract_domain(reply_to)
    return_path_domain = extract_domain(return_path)

    # 1. Header Mismatch Analysis
    mismatches = []
    domain_mismatch_score = 0
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        mismatches.append({
            'type': 'From vs Reply-To Mismatch',
            'detail': f"Sender displays '@{from_domain}' but replies redirect to '@{reply_to_domain}'",
            'severity': 'High'
        })
        domain_mismatch_score += 35

    if return_path_domain and from_domain and return_path_domain != from_domain:
        mismatches.append({
            'type': 'From vs Return-Path Mismatch',
            'detail': f"Bounce destination is '@{return_path_domain}', differing from sender '@{from_domain}'",
            'severity': 'Medium'
        })
        domain_mismatch_score += 20

    # 2. Authentication Analysis (SPF/DKIM/DMARC)
    auth_results = parse_auth_results(raw_content)
    auth_score = 0
    if auth_results['spf']['status'].lower() in ['fail', 'softfail']:
        auth_score += 25
    if auth_results['dkim']['status'].lower() in ['fail', 'bad']:
        auth_score += 25
    if auth_results['dmarc']['status'].lower() in ['fail', 'reject']:
        auth_score += 30

    # 3. Received Chain Hops & Journey Timeline
    hops = parse_received_hops(msg)

    # 4. Link & Deception Analysis
    link_mismatches = find_link_mismatches(raw_content)
    link_score = 35 if link_mismatches else 0

    # 5. Attachment Analysis
    risky_attachments = find_risky_attachments(raw_content, raw_content)
    attachment_score = 30 if risky_attachments else 0

    # 6. Urgency & Threat Language Analysis
    urgency_findings, urgency_score = analyze_urgency_language(raw_content)

    # Total Risk Calculation (capped at 100)
    total_score = min(100, domain_mismatch_score + auth_score + link_score + attachment_score + urgency_score)
    
    # Verdict Assignment
    if total_score >= 65:
        verdict = 'Malicious'
        verdict_class = 'danger'
    elif total_score >= 35:
        verdict = 'Suspicious'
        verdict_class = 'warning'
    else:
        verdict = 'Safe'
        verdict_class = 'success'

    return {
        'subject': subject,
        'from': from_header,
        'reply_to': reply_to or 'None specified',
        'return_path': return_path or 'None specified',
        'date': date_header,
        'verdict': verdict,
        'verdict_class': verdict_class,
        'risk_score': round(total_score, 1),
        'domain_mismatches': mismatches,
        'authentication': auth_results,
        'hops': hops,
        'link_mismatches': link_mismatches,
        'risky_attachments': risky_attachments,
        'urgency_findings': urgency_findings
    }
