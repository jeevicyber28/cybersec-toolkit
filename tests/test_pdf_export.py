from app.services.pdf_generator import generate_history_pdf

def test_pdf_report_generation():
    mock_scans = [
        {
            'tool_type': 'url',
            'target': 'https://google.com',
            'risk_score': 5.0,
            'verdict': 'Safe',
            'created_at': '2026-10-28 10:00:00'
        },
        {
            'tool_type': 'email',
            'target': 'Urgent: Wire Transfer Request',
            'risk_score': 85.0,
            'verdict': 'Malicious',
            'created_at': '2026-10-28 10:05:00'
        }
    ]

    pdf_bytes = generate_history_pdf(mock_scans, username='LeadAuditor', safety_score=88)
    assert isinstance(pdf_bytes, bytes)
    # Valid PDF magic header
    assert pdf_bytes.startswith(b'%PDF-')
    assert len(pdf_bytes) > 1000

def test_pdf_export_route(auth_client):
    c, user_id = auth_client
    res = c.get('/history/export/pdf')
    assert res.status_code == 200
    assert res.content_type == 'application/pdf'
    assert res.data.startswith(b'%PDF-')
