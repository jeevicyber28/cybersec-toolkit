import json
from flask import Blueprint, render_template, request, flash
from flask_login import current_user
from app import db
from app.models import ScanHistory
from app.services.email_parser import analyze_email

email_analyzer_bp = Blueprint('email_analyzer', __name__)

SAMPLE_SUSPICIOUS_EMAIL = """Received: from mail-relay.evil-phish.ru ([185.220.101.5])
    by mx.google.com with ESMTPS id abc123xyz
    for <victim@example.com>; Wed, 28 Oct 2026 09:30:00 +0000
Received: from unknown-origin.net ([10.0.0.99])
    by mail-relay.evil-phish.ru with ESMTP; Wed, 28 Oct 2026 09:29:45 +0000
Authentication-Results: mx.google.com;
    spf=fail (google.com: domain of support@paypal-alert-security.com does not designate 185.220.101.5 as permitted sender);
    dkim=fail;
    dmarc=fail (p=REJECT)
From: "PayPal Security Support" <support@paypal.com>
Reply-To: billing-fraud-desk@evil-phish.ru
Return-Path: <bounce@untrusted-host.net>
Subject: URGENT: Your PayPal Account will be suspended within 24 hours!
Date: Wed, 28 Oct 2026 09:30:00 +0000
Content-Type: text/html; charset=UTF-8

<p>Dear Customer,</p>
<p>We detected unauthorized activity on your PayPal account. You must verify your credentials immediately or your funds will be permanently frozen.</p>
<p>Click here to resolve: <a href="http://evil-phish.ru/harvest-login">https://www.paypal.com/security-verify</a></p>
<p>Please review the attached invoice: invoice_details.pdf.exe</p>
"""

SAMPLE_SAFE_EMAIL = """Received: from out-1.mail.github.com ([192.30.252.201])
    by mx.google.com with ESMTPS id git9283
    for <dev@example.com>; Wed, 28 Oct 2026 08:00:00 +0000
Authentication-Results: mx.google.com;
    spf=pass (google.com: domain of notifications@github.com designates 192.30.252.201 as permitted sender);
    dkim=pass header.i=@github.com;
    dmarc=pass (p=REJECT)
From: GitHub Notifications <notifications@github.com>
Reply-To: support@github.com
Return-Path: <bounces@github.com>
Subject: [GitHub] Security advisory alert for repository
Date: Wed, 28 Oct 2026 08:00:00 +0000
Content-Type: text/html; charset=UTF-8

<p>Hi developer,</p>
<p>A new security advisory has been published for one of your dependencies. You can review the details on GitHub at <a href="https://github.com/advisories">https://github.com/advisories</a>.</p>
"""

@email_analyzer_bp.route('/', methods=['GET', 'POST'])
def index():
    result = None
    raw_content = ''

    if request.method == 'POST':
        raw_content = request.form.get('raw_email', '').strip()
        if not raw_content:
            flash('Please paste the raw email headers and/or body to analyze.', 'warning')
        else:
            result = analyze_email(raw_content)

            if current_user.is_authenticated:
                history_entry = ScanHistory(
                    user_id=current_user.id,
                    tool_type='email',
                    target=(result['subject'] or 'Email Analysis')[:250],
                    verdict=result['verdict'],
                    risk_score=result['risk_score'],
                    details_json=json.dumps({
                        'subject': result['subject'],
                        'from': result['from'],
                        'reply_to': result['reply_to'],
                        'hops_count': len(result['hops']),
                        'link_mismatches_count': len(result['link_mismatches']),
                        'risky_attachments_count': len(result['risky_attachments']),
                        'urgency_count': len(result['urgency_findings'])
                    })
                )
                db.session.add(history_entry)
                db.session.commit()

    return render_template(
        'tools/email_analyzer.html',
        result=result,
        raw_content=raw_content,
        sample_suspicious=SAMPLE_SUSPICIOUS_EMAIL,
        sample_safe=SAMPLE_SAFE_EMAIL
    )
