"""
Unit Tests for PrivaVend Cashu Engine (NUT-00, NUT-01, NUT-02, NUT-03, NUT-07).
"""

import pytest
from worker.core.cashu import (
    CashuMintClient,
    CashuVault,
    CashuVerificationError,
    Proof,
    decode_token,
    encode_token_v3,
    hash_to_curve,
    negate_point,
    split_amount_into_powers_of_two,
)


def test_hash_to_curve():
    """Verifies that hash_to_curve returns a valid compressed 33-byte curve point."""
    secret = b"test_secret_for_cashu"
    point = hash_to_curve(secret)
    assert len(point) == 33
    assert point[0] == 0x02  # NUT-00 specifies even Y


def test_negate_point():
    """Verifies point negation flips prefix between 0x02 and 0x03."""
    dummy_02 = b"\x02" + b"\x11" * 32
    neg_02 = negate_point(dummy_02)
    assert neg_02[0] == 0x03
    assert neg_02[1:] == dummy_02[1:]

    dummy_03 = b"\x03" + b"\x22" * 32
    neg_03 = negate_point(dummy_03)
    assert neg_03[0] == 0x02


def test_split_amount():
    """Verifies amount decomposition into powers of two."""
    assert split_amount_into_powers_of_two(1) == [1]
    assert split_amount_into_powers_of_two(5) == [1, 4]
    assert split_amount_into_powers_of_two(13) == [1, 4, 8]
    assert sum(split_amount_into_powers_of_two(42)) == 42


def test_token_encode_decode():
    """Verifies Cashu NUT-00 V3 token roundtrip encoding and decoding."""
    proofs = [
        Proof(id="keyset_01", amount=2, secret="s1", C="02" + "aa" * 32),
        Proof(id="keyset_01", amount=8, secret="s2", C="02" + "bb" * 32),
    ]
    mint = "https://mint.example.com"
    token_str = encode_token_v3(mint, proofs, memo="Payment for AI inference")

    assert token_str.startswith("cashuA")

    decoded = decode_token(token_str)
    assert decoded.total_amount == 10
    assert decoded.primary_mint == "https://mint.example.com"
    assert len(decoded.all_proofs) == 2
    assert decoded.memo == "Payment for AI inference"


def test_invalid_token():
    """Verifies error handling on malformed tokens."""
    with pytest.raises(CashuVerificationError):
        decode_token("cashuAinvalidbase64content!!!")


@pytest.mark.asyncio
async def test_mint_swap_and_vault():
    """Verifies atomic swap simulation and vault balance tracking."""
    client = CashuMintClient("https://mock.mint", allow_mock_fallback=True)

    input_proofs = [
        Proof(id="mock_keyset_001", amount=1, secret="sec1", C="02" + "11" * 32),
        Proof(id="mock_keyset_001", amount=4, secret="sec2", C="02" + "22" * 32),
    ]

    new_proofs, settled_sats = await client.swap_proofs(input_proofs)
    assert settled_sats == 5
    assert len(new_proofs) == 2  # 1 and 4

    vault = CashuVault()
    assert vault.balance == 0
    vault.add_settled_proofs(new_proofs)
    assert vault.balance == 5
    assert vault.total_earned == 5


@pytest.mark.asyncio
async def test_checkstate():
    """Verifies proof state check (NUT-07)."""
    client = CashuMintClient("https://mock.mint", allow_mock_fallback=True)
    proofs = [Proof(id="mock", amount=1, secret="abc", C="02" + "33" * 32)]
    states = await client.check_proof_states(proofs)
    assert len(states) == 1
    assert states[0]["state"] == "UNSPENT"
