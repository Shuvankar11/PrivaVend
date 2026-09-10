"""
Unit Tests for PrivaVend Nostr Engine (NIP-01, NIP-44 v2, NIP-90, BIP-173).
"""

import os
import secrets
import time
import coincurve
import pytest
from worker.core.nostr import (
    NostrEvent,
    bech32_decode,
    bech32_decode_nsec,
    bech32_encode,
    compute_conversation_key,
    create_job_feedback_event,
    create_job_result_event,
    nip44_decrypt,
    nip44_encrypt,
    parse_job_request,
    privkey_to_nsec,
    pubkey_to_npub,
    schnorr_sign,
    schnorr_verify,
)


def test_bech32_roundtrip():
    """Verifies Bech32 npub and nsec encoding/decoding."""
    raw_key = bytes.fromhex("1a030070216cb762e856bfbd1837bbdb77bc67c74b3c95988c10d1d056e64a78")
    npub = pubkey_to_npub(raw_key.hex())
    assert npub.startswith("npub1")
    hrp, decoded = bech32_decode(npub)
    assert hrp == "npub"
    assert decoded == raw_key

    nsec = privkey_to_nsec(raw_key.hex())
    assert nsec.startswith("nsec1")
    decoded_nsec_hex = bech32_decode_nsec(nsec)
    assert decoded_nsec_hex == raw_key.hex()


def test_schnorr_signatures():
    """Verifies BIP-340 Schnorr signing and verification."""
    sk_bytes = secrets.token_bytes(32)
    pk_bytes = coincurve.PrivateKey(sk_bytes).public_key.format(compressed=True)[1:]
    msg = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    sig = schnorr_sign(msg, sk_bytes)
    assert len(sig) == 64
    assert schnorr_verify(msg, pk_bytes, sig) is True

    # Bad message should fail verification
    bad_msg = bytes.fromhex("00" * 32)
    assert schnorr_verify(bad_msg, pk_bytes, sig) is False


def test_nostr_event_lifecycle():
    """Verifies NIP-01 Nostr event serialization, signing, and verification."""
    sk_bytes = secrets.token_bytes(32)
    pk_hex = coincurve.PrivateKey(sk_bytes).public_key.format(compressed=True)[1:].hex()

    event = NostrEvent(
        pubkey=pk_hex,
        created_at=int(time.time()),
        kind=1,
        tags=[["t", "privavend"]],
        content="Autonomous zero-trace DVM live on Nostr!",
    )
    event.sign(sk_bytes)

    assert len(event.id) == 64
    assert len(event.sig) == 128
    assert event.verify() is True

    # Modifying content invalidates signature
    event.content = "Tampered content"
    assert event.verify() is False


def test_nip44_v2_encryption():
    """Verifies NIP-44 v2 authenticated ChaCha20 roundtrip encryption and decryption."""
    # Alice keypair
    sk_alice = secrets.token_bytes(32)
    pk_alice = coincurve.PrivateKey(sk_alice).public_key.format(compressed=True)[1:]

    # Bob keypair
    sk_bob = secrets.token_bytes(32)
    pk_bob = coincurve.PrivateKey(sk_bob).public_key.format(compressed=True)[1:]

    # Derive symmetric conversation keys
    conv_alice = compute_conversation_key(sk_alice, pk_bob)
    conv_bob = compute_conversation_key(sk_bob, pk_alice)
    assert conv_alice == conv_bob

    plaintext = "Cypherpunks write code. PrivaVend delivers zero-trace AI inference."
    encrypted_b64 = nip44_encrypt(conv_alice, plaintext)

    decrypted = nip44_decrypt(conv_bob, encrypted_b64)
    assert decrypted == plaintext

    # Corrupted ciphertext should fail HMAC authentication
    corrupted = bytearray(os.urandom(80))
    corrupted[0] = 0x02
    import base64
    with pytest.raises(ValueError):
        nip44_decrypt(conv_bob, base64.b64encode(corrupted).decode())


def test_nip90_job_parsing():
    """Verifies NIP-90 Kind 5000 job parsing from Nostr events."""
    sk = secrets.token_bytes(32)
    pk = coincurve.PrivateKey(sk).public_key.format(compressed=True)[1:].hex()

    event = NostrEvent(
        pubkey=pk,
        created_at=int(time.time()),
        kind=5000,
        tags=[
            ["i", "Summarize Nostr NIP-90 spec", "text"],
            ["cashu", "cashuAeyJ0b2tlbiI6W3sibWludCI6Imh0dHA6Ly9taW50IiwicHJvb2ZzIjpbXX1dfQ=="],
            ["param", "model", "mistral"],
            ["p", "worker_pubkey_123"],
            ["bid", "5000"],
        ],
        content="Summarize Nostr NIP-90 spec",
    )
    event.sign(sk)

    job = parse_job_request(event, worker_pubkey="worker_pubkey_123")
    assert job is not None
    assert job.prompt == "Summarize Nostr NIP-90 spec"
    assert job.model == "mistral"
    assert job.cashu_token.startswith("cashuA")
    assert job.is_targeted is True
    assert job.bid_amount_msats == 5000


def test_nip90_feedback_and_result_generation():
    """Verifies Kind 7000 feedback and Kind 6000 encrypted result generation."""
    worker_sk = secrets.token_bytes(32)
    worker_pk = coincurve.PrivateKey(worker_sk).public_key.format(compressed=True)[1:].hex()

    client_sk = secrets.token_bytes(32)
    client_pk = coincurve.PrivateKey(client_sk).public_key.format(compressed=True)[1:].hex()

    req_id = "a1b2c3d4e5f600112233445566778899aabbccddeeff00112233445566778899"

    # Kind 7000 feedback
    fb = create_job_feedback_event(
        worker_pubkey=worker_pk,
        worker_privkey_bytes=worker_sk,
        request_event_id=req_id,
        customer_pubkey=client_pk,
        status="processing",
        message="Running model...",
    )
    assert fb.kind == 7000
    assert fb.verify() is True

    # Kind 6000 encrypted result
    res = create_job_result_event(
        worker_pubkey=worker_pk,
        worker_privkey_bytes=worker_sk,
        request_event_id=req_id,
        customer_pubkey=client_pk,
        prompt="Test Prompt",
        result_text="Secret AI Result Payload",
        settled_sats=10,
        encrypt_response=True,
    )
    assert res.kind == 6000
    assert res.verify() is True
    assert any(t[0] == "encrypted" for t in res.tags)

    # Client decrypts
    client_conv = compute_conversation_key(client_sk, bytes.fromhex(worker_pk))
    plain = nip44_decrypt(client_conv, res.content)
    assert plain == "Secret AI Result Payload"
