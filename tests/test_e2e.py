"""
End-to-end Integration Test for PrivaVend Daemon and Client Flow.
Simulates end-to-end event exchange, ecash settlement, AI generation, and NIP-44 v2 decryption.
"""

import asyncio
import secrets
import coincurve
import pytest
from worker.config import Settings
from worker.core.ai_engine import AIEngine
from worker.core.cashu import Proof, encode_token_v3
from worker.core.nostr import (
    NostrEvent,
    compute_conversation_key,
    nip44_decrypt,
    parse_job_request,
)
from worker.main import PrivaVendDaemon


@pytest.mark.asyncio
async def test_end_to_end_job_processing():
    # 1. Initialize Worker Settings with mock support enabled
    settings = Settings(
        nostr_private_key="",  # Ephemeral
        cashu_mint_url="https://mock.mint",
        cashu_min_fee_sats=2,
        cashu_auto_swap=True,
        cashu_allow_mock_fallback=True,
        ai_backend="mock",
        ai_model="llama3",
    )
    settings.initialize_identity()
    daemon = PrivaVendDaemon(settings)

    # 2. Setup Client Identity
    client_sk = secrets.token_bytes(32)
    client_pk = coincurve.PrivateKey(client_sk).public_key.format(compressed=True)[1:].hex()

    # 3. Create a 5-sat Cashu Ecash Token
    proofs = [
        Proof(id="test_keyset_001", amount=1, secret="s1", C="02" + "11" * 32),
        Proof(id="test_keyset_001", amount=4, secret="s2", C="02" + "22" * 32),
    ]
    cashu_token = encode_token_v3("https://mock.mint", proofs)

    # 4. Generate Client Kind 5000 Job Request
    prompt = "Conduct a security audit of an atomic escrow contract."
    req_event = NostrEvent(
        pubkey=client_pk,
        created_at=1000000,
        kind=5000,
        tags=[
            ["i", prompt, "text"],
            ["cashu", cashu_token],
            ["param", "model", "llama3"],
            ["p", settings.public_key_hex],
        ],
        content=prompt,
    )
    req_event.sign(client_sk)

    # 5. Track Broadcast Events
    broadcasted_events: list[NostrEvent] = []

    async def mock_broadcast(event: NostrEvent):
        broadcasted_events.append(event)

    daemon.relay_pool.broadcast_event = mock_broadcast

    # 6. Process the Job Event via Daemon
    await daemon._process_job(req_event)

    # 7. Validate Outbound Events
    # Expect: 1) processing feedback (Kind 7000)
    #         2) result event (Kind 6000)
    #         3) success feedback (Kind 7000)
    assert len(broadcasted_events) >= 2

    # Check feedback events
    feedback_events = [e for e in broadcasted_events if e.kind == 7000]
    assert any("processing" in [t[1] for t in e.tags if t[0] == "status"] for e in feedback_events)

    # Check result event
    result_events = [e for e in broadcasted_events if e.kind == 6000]
    assert len(result_events) == 1
    result_ev = result_events[0]

    # Verify event authenticity and tags
    assert result_ev.verify() is True
    assert any(t[0] == "e" and t[1] == req_event.id for t in result_ev.tags)
    assert any(t[0] == "p" and t[1] == client_pk for t in result_ev.tags)
    assert any(t[0] == "encrypted" for t in result_ev.tags)
    assert any(t[0] == "amount" and t[1] == "5" for t in result_ev.tags)

    # 8. Client Decrypts Response via NIP-44 v2
    conv_key = compute_conversation_key(client_sk, bytes.fromhex(settings.public_key_hex))
    decrypted_response = nip44_decrypt(conv_key, result_ev.content)

    assert "Cyber-Audit Engine" in decrypted_response
    assert "Cryptographic & Security Verification Report" in decrypted_response

    # 9. Verify Vault Settled Sats
    assert daemon.vault.balance == 5
    assert daemon.vault.total_earned == 5
