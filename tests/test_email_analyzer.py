from app.services.email_parser import analyze_email

def test_email_spoofing_and_hops():
    raw_sample = """Received: from mail-relay.evil-phish.ru ([185.220.101.5])
    by mx.google.com with ESMTPS id abc123xyz
    for <victim@example.com>; Wed, 28 Oct 2026 09:30:00 +0000
Received: from unknown-origin.net ([10.0.0.99])
    by mail-relay.evil-phish.ru with ESMTP; Wed, 28 Oct 2026 09:29:45 +0000
Authentication-Results: mx.google.com;
    spf=fail;
    dkim=fail;
    dmarc=fail (p=REJECT)
From: "PayPal Security" <support@paypal.com>
Reply-To: fraudster@evil-phish.ru
Return-Path: <bounce@untrusted.com>
Subject: URGENT: Your PayPal Account will be suspended within 24 hours!
Date: Wed, 28 Oct 2026 09:30:00 +0000
Content-Type: text/html

<p>Confirm account: <a href="http://evil-phish.ru/login">https://paypal.com/verify</a></p>
<p>File: payload.zip.exe</p>
"""
    result = analyze_email(raw_sample)

    assert result['verdict'] == 'Malicious'
    assert result['risk_score'] >= 70
    assert len(result['domain_mismatches']) >= 1
    assert result['authentication']['spf']['status'].lower() == 'fail'
    assert result['authentication']['dkim']['status'].lower() == 'fail'
    assert result['authentication']['dmarc']['status'].lower() == 'fail'
    assert len(result['hops']) == 2
    assert len(result['link_mismatches']) >= 1
    assert len(result['risky_attachments']) >= 1
    assert len(result['urgency_findings']) >= 1

def test_safe_email_parsing():
    raw_sample = """Received: from out-1.mail.github.com ([192.30.252.201])
    by mx.google.com with ESMTPS id git9283
    for <dev@example.com>; Wed, 28 Oct 2026 08:00:00 +0000
Authentication-Results: mx.google.com;
    spf=pass;
    dkim=pass;
    dmarc=pass (p=REJECT)
From: GitHub Notifications <notifications@github.com>
Reply-To: support@github.com
Return-Path: <bounces@github.com>
Subject: [GitHub] Security update
Date: Wed, 28 Oct 2026 08:00:00 +0000

<p>Review update: <a href="https://github.com/advisories">https://github.com/advisories</a></p>
"""
    result = analyze_email(raw_sample)
    assert result['verdict'] == 'Safe'
    assert result['risk_score'] < 35
    assert len(result['domain_mismatches']) == 0
    assert result['authentication']['spf']['status'].lower() == 'pass'

def test_email_analyzer_route(client):
    res = client.get('/email-analyzer/')
    assert res.status_code == 200
    assert b'Email Journey &amp; Header Analyzer' in res.data
