import pytest
import io
from app.services.hash_service import generate_hashes, identify_hash, verify_file_checksum

def test_generate_hashes():
    data = b'hello cyber security'
    hashes = generate_hashes(data)
    assert 'md5' in hashes
    assert 'sha1' in hashes
    assert 'sha256' in hashes
    assert 'sha512' in hashes
    assert 'sha3_256' in hashes
    assert 'blake2b' in hashes
    assert len(hashes['sha256']) == 64

def test_identify_hash():
    # 32 char MD5
    matches = identify_hash('5d41402abc4b2a76b9719d911017c592')
    assert any('MD5' in m['algorithm'] for m in matches)

    # 64 char SHA-256
    matches256 = identify_hash('ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f')
    assert any('SHA-256' in m['algorithm'] for m in matches256)

    # Bcrypt
    matches_bcrypt = identify_hash('$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW')
    assert any('bcrypt' in m['algorithm'] for m in matches_bcrypt)

def test_verify_file_checksum():
    data = b'verifiable content payload'
    hashes = generate_hashes(data)
    # Correct checksum
    res_ok = verify_file_checksum(data, hashes['sha256'])
    assert res_ok['match'] is True
    assert res_ok['algorithm'] == 'SHA256'

    # Mismatched checksum
    res_bad = verify_file_checksum(data, '0000000000000000000000000000000000000000000000000000000000000000')
    assert res_bad['match'] is False

def test_hash_studio_routes(client):
    get_resp = client.get('/hash-studio/')
    assert get_resp.status_code == 200
    assert b'Cryptographic Hash Studio' in get_resp.data

    post_resp = client.post('/hash-studio/', data={'action': 'generate', 'raw_text': 'test hash string'})
    assert post_resp.status_code == 200
    assert b'Generated Cryptographic Digests' in post_resp.data
