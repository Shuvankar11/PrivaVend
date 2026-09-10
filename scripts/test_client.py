"""
PrivaVend CLI Test Client
Simulates a client sending a NIP-90 Job Request (Kind 5000) with a Cashu Ecash Token,
streaming feedback events (Kind 7000), and decrypting the final AI result (Kind 6000) via NIP-44 v2.
"""

import argparse
import asyncio
import json
import logging
import os
import secrets
import sys
import time
from typing import Optional
import coincurve
import websockets

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from worker.core.cashu import Proof, encode_token_v3
from worker.core.nostr import (
    NostrEvent,
    bech32_decode,
    compute_conversation_key,
    nip44_decrypt,
    privkey_to_nsec,
    pubkey_to_npub,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("test_client")


def generate_mock_cashu_token(mint_url: str, amount_sats: int = 5) -> str:
    """Generates a test Cashu token with deterministic proofs for development and testing."""
    proofs = []
    # Split amount into 1-sat proofs or binary powers
    for i in range(amount_sats):
        sec = secrets.token_hex(16)
        # 33-byte mock compressed signature point
        mock_c = "02" + secrets.token_hex(32)
        proofs.append(Proof(
            id="test_keyset_001",
            amount=1,
            secret=sec,
            C=mock_c,
        ))
    return encode_token_v3(mint_url, proofs, memo="PrivaVend Boss Battle Test")


async def run_client(
    prompt: str,
    cashu_token: str,
    relays: list[str],
    worker_pubkey: Optional[str] = None,
    client_privkey_hex: Optional[str] = None,
    model: Optional[str] = None,
    timeout_secs: float = 45.0,
) -> None:
    # 1. Setup client cryptographic identity
    if client_privkey_hex:
        sk_bytes = bytes.fromhex(client_privkey_hex)
    else:
        sk_bytes = secrets.token_bytes(32)

    priv = coincurve.PrivateKey(sk_bytes)
    client_pubkey_hex = priv.public_key.format(compressed=True)[1:].hex()
    client_npub = pubkey_to_npub(client_pubkey_hex)

    logger.info("=========================================================")
    logger.info("PrivaVend Test Client Initialized")
    logger.info("Client Pubkey: %s", client_pubkey_hex)
    logger.info("Client npub:   %s", client_npub)
    logger.info("Relays:        %s", relays)
    logger.info("Prompt:        '%s'", prompt)
    if worker_pubkey:
        logger.info("Target Worker: %s", worker_pubkey)
    logger.info("=========================================================")

    # 2. Build NIP-90 Kind 5000 Job Request Event
    tags = [
        ["i", prompt, "text"],
        ["cashu", cashu_token],
        ["output", "text/plain"],
    ]
    if worker_pubkey:
        # Handle npub if provided
        target_hex = worker_pubkey
        if worker_pubkey.startswith("npub"):
            hrp, raw = bech32_decode(worker_pubkey)
            target_hex = raw.hex()
        tags.append(["p", target_hex])

    if model:
        tags.append(["param", "model", model])

    req_event = NostrEvent(
        pubkey=client_pubkey_hex,
        created_at=int(time.time()),
        kind=5000,
        tags=tags,
        content=prompt,
    )
    req_event.sign(sk_bytes)
    logger.info("Generated Kind 5000 Job Request ID: %s", req_event.id)

    # 3. Connect to Relay and Subscribe
    primary_relay = relays[0]
    logger.info("Connecting to primary relay: %s", primary_relay)

    try:
        async with websockets.connect(primary_relay, ping_interval=20) as ws:
            logger.info("Connected to %s", primary_relay)

            # Subscribe to Kind 7000 (Feedback) and Kind 6000 (Result) referencing our job request ID
            sub_id = f"client_sub_{secrets.token_hex(4)}"
            sub_filter = {
                "kinds": [6000, 7000],
                "#e": [req_event.id],
            }
            await ws.send(json.dumps(["REQ", sub_id, sub_filter]))
            logger.info("Subscribed for responses with filter: %s", sub_filter)

            # Broadcast our Kind 5000 request event
            await ws.send(json.dumps(["EVENT", req_event.model_dump()]))
            logger.info("Kind 5000 Job Request broadcasted! Awaiting daemon processing...")

            start_time = time.time()
            while time.time() - start_time < timeout_secs:
                try:
                    raw_msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
                    msg = json.loads(raw_msg)
                    if not isinstance(msg, list) or len(msg) < 3:
                        continue

                    msg_type = msg[0]
                    if msg_type != "EVENT":
                        continue

                    event_dict = msg[2]
                    event = NostrEvent.model_validate(event_dict)

                    if event.kind == 7000:
                        # Extract status tag
                        status = "unknown"
                        for t in event.tags:
                            if t[0] == "status" and len(t) > 1:
                                status = t[1]
                        logger.info(">>> [FEEDBACK - Kind 7000] Status: '%s' | Content: %s", status, event.content)

                    elif event.kind == 6000:
                        logger.info(">>> [RESULT - Kind 6000] Job Result Event Received from %s!", event.pubkey[:8])

                        # Check if encrypted with NIP-44
                        is_encrypted = any(t[0] == "encrypted" for t in event.tags)
                        if is_encrypted:
                            logger.info("Decrypting response via NIP-44 v2...")
                            conv_key = compute_conversation_key(sk_bytes, bytes.fromhex(event.pubkey))
                            decrypted_text = nip44_decrypt(conv_key, event.content)
                            print("\n" + "=" * 60)
                            print("PRIVAVEND AI INFERENCE RESULT (DECRYPTED):")
                            print("=" * 60)
                            print(decrypted_text)
                            print("=" * 60 + "\n")
                        else:
                            print("\n" + "=" * 60)
                            print("PRIVAVEND AI INFERENCE RESULT (PLAINTEXT):")
                            print("=" * 60)
                            print(event.content)
                            print("=" * 60 + "\n")

                        # Extract settled amount
                        for t in event.tags:
                            if t[0] == "amount" and len(t) > 1:
                                logger.info("Settled Value: %s sats", t[1])

                        logger.info("Test Client Completed Successfully in %.2fs!", time.time() - start_time)
                        return

                except asyncio.TimeoutError:
                    elapsed = time.time() - start_time
                    logger.info("Waiting for DVM response... (%.1fs elapsed)", elapsed)

            logger.error("Timed out waiting for response from relay.")

    except Exception as e:
        logger.error("Client error: %s", e, exc_info=True)


def main():
    parser = argparse.ArgumentParser(description="PrivaVend NIP-90 + Cashu Test Client")
    parser.add_argument(
        "--prompt",
        type=str,
        default="Audit this Bitcoin smart contract: OP_IF 2 <pk1> <pk2> 2 OP_CHECKMULTISIG OP_ELSE <timeout> OP_CHECKSEQUENCEVERIFY OP_DROP <pk1> OP_CHECKSIG OP_ENDIF",
        help="Prompt to send to PrivaVend DVM",
    )
    parser.add_argument(
        "--token",
        type=str,
        default="",
        help="Cashu Ecash token (cashuA...). If omitted, a mock 5-sat token is generated.",
    )
    parser.add_argument(
        "--mint",
        type=str,
        default="https://mint.minibits.cash/Bitcoin",
        help="Cashu Mint URL",
    )
    parser.add_argument(
        "--sats",
        type=int,
        default=5,
        help="Sats denomination for generated mock token",
    )
    parser.add_argument(
        "--relays",
        type=str,
        default="wss://relay.damus.io,wss://nos.lol",
        help="Comma-separated WebSocket relay URLs",
    )
    parser.add_argument(
        "--worker-pubkey",
        type=str,
        default=None,
        help="Optional worker public key (hex or npub) to target specific DVM",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Optional AI model name parameter (e.g. llama3)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=45.0,
        help="Timeout in seconds",
    )

    args = parser.parse_args()

    token = args.token.strip()
    if not token:
        logger.info("No token provided. Generating mock %d-sat Cashu token...", args.sats)
        token = generate_mock_cashu_token(args.mint, amount_sats=args.sats)
        logger.info("Generated Cashu Token: %s...", token[:35])

    relays_list = [r.strip() for r in args.relays.split(",") if r.strip()]

    asyncio.run(
        run_client(
            prompt=args.prompt,
            cashu_token=token,
            relays=relays_list,
            worker_pubkey=args.worker_pubkey,
            model=args.model,
            timeout_secs=args.timeout,
        )
    )


if __name__ == "__main__":
    main()
