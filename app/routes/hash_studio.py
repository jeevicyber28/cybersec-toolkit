from flask import Blueprint, render_template, request, flash
from app.services.hash_service import generate_hashes, identify_hash, verify_file_checksum

hash_studio_bp = Blueprint('hash_studio', __name__)

@hash_studio_bp.route('/', methods=['GET', 'POST'])
def index():
    active_tab = 'generator'
    gen_results = None
    gen_text = ''
    ident_results = None
    ident_input = ''
    verify_results = None
    expected_input = ''

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'generate':
            active_tab = 'generator'
            gen_text = request.form.get('raw_text', '')
            file = request.files.get('file_upload')

            if file and file.filename:
                file_bytes = file.read()
                gen_results = generate_hashes(file_bytes)
                gen_text = f"File: {file.filename} ({len(file_bytes):,} bytes)"
            elif gen_text:
                gen_results = generate_hashes(gen_text.encode('utf-8'))
            else:
                flash('Please enter text or upload a file to hash.', 'warning')

        elif action == 'identify':
            active_tab = 'identifier'
            ident_input = request.form.get('hash_string', '').strip()
            if not ident_input:
                flash('Please enter a hash string to identify.', 'warning')
            else:
                ident_results = identify_hash(ident_input)

        elif action == 'verify':
            active_tab = 'verifier'
            expected_input = request.form.get('expected_hash', '').strip()
            file = request.files.get('verify_file')

            if not file or not file.filename:
                flash('Please upload a file to verify.', 'warning')
            elif not expected_input:
                flash('Please enter the expected checksum.', 'warning')
            else:
                file_bytes = file.read()
                verify_results = verify_file_checksum(file_bytes, expected_input)
                verify_results['filename'] = file.filename
                verify_results['filesize'] = len(file_bytes)

    return render_template(
        'tools/hash_studio.html',
        active_tab=active_tab,
        gen_results=gen_results,
        gen_text=gen_text,
        ident_results=ident_results,
        ident_input=ident_input,
        verify_results=verify_results,
        expected_input=expected_input
    )
