"""
PrivaVend Nostr Core Protocol Engine
Implements:
- NIP-01: Canonical event serialization, BIP-340 Schnorr signatures, WebSocket Relay Client
- NIP-44 (Version 2): ChaCha20-HKDF-HMAC authenticated payload encryption
- NIP-90: Data Vending Machine (DVM) Kind 5000 request parser, Kind 7000 feedback, Kind 6000 results
- BIP-173: Bech32 npub/nsec encoder/decoder
"""

import asyncio
import base64
import hashlib
import hmac as py_hmac
import json
import logging
import os
import re
import secrets
import time
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple
import coincurve
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives import hashes
from pydantic import BaseModel, Field
import websockets

logger = logging.getLogger("privavend.nostr")

# Bech32 Constants
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


# ==============================================================================
# BIP-173 Bech32 Encoding / Decoding
# ==============================================================================

def _bech32_polymod(values: List[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp: str, data: List[int]) -> List[int]:
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _bech32_verify_checksum(hrp: str, data: List[int]) -> bool:
    return _bech32_polymod(_bech32_hrp_expand(hrp) + data) == 1


def _convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> Optional[List[int]]:
    acc = 0
    bits = 0
    ret: List[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bech32_encode(hrp: str, data_bytes: bytes) -> str:
    """Encodes arbitrary bytes to a Bech32 string with specified HRP."""
    data_5bit = _convertbits(data_bytes, 8, 5, True)
    if data_5bit is None:
        raise ValueError("Failed to convert bits for Bech32")
    combined = data_5bit + _bech32_create_checksum(hrp, data_5bit)
    return hrp + "1" + "".join([BECH32_CHARSET[d] for d in combined])


def bech32_decode(bech_str: str) -> Tuple[str, bytes]:
    """Decodes a Bech32 string into (hrp, raw_bytes)."""
    pos = bech_str.rfind("1")
    if pos < 1 or pos + 7 > len(bech_str) or len(bech_str) > 90:
        raise ValueError("Invalid Bech32 string length or separator position")
    hrp = bech_str[:pos].lower()
    data: List[int] = []
    for x in bech_str[pos + 1 :].lower():
        idx = BECH32_CHARSET.find(x)
        if idx == -1:
            raise ValueError(f"Invalid Bech32 character: {x}")
        data.append(idx)
    if not _bech32_verify_checksum(hrp, data):
        raise ValueError("Invalid Bech32 checksum")
    raw_5bit = data[:-6]
    converted = _convertbits(bytes(raw_5bit), 5, 8, False)
    if converted is None:
        raise ValueError("Invalid bit padding in Bech32 string")
    return hrp, bytes(converted)


def bech32_decode_nsec(nsec_str: str) -> str:
    """Decodes an nsec1... string to a 64-character hex private key."""
    hrp, raw = bech32_decode(nsec_str)
    if hrp != "nsec" or len(raw) != 32:
        raise ValueError(f"Expected nsec HRP with 32 bytes, got {hrp} with {len(raw)} bytes")
    return raw.hex()


def pubkey_to_npub(pubkey_hex: str) -> str:
    """Converts a 32-byte hex public key to an npub1... string."""
    return bech32_encode("npub", bytes.fromhex(pubkey_hex))


def privkey_to_nsec(privkey_hex: str) -> str:
    """Converts a 32-byte hex private key to an nsec1... string."""
    return bech32_encode("nsec", bytes.fromhex(privkey_hex))


# ==============================================================================
# BIP-340 Schnorr Signatures & Verification (libsecp256k1 Native)
# ==============================================================================

def schnorr_sign(msg_32: bytes, privkey_32: bytes) -> bytes:
    """Signs a 32-byte message hash using BIP-340 Schnorr via native libsecp256k1."""
    if len(msg_32) != 32 or len(privkey_32) != 32:
        raise ValueError("Both message hash and private key must be exactly 32 bytes")
    sk = coincurve.PrivateKey(privkey_32)
    return sk.sign_schnorr(msg_32)


def schnorr_verify(msg_32: bytes, pubkey_xonly_32: bytes, sig_64: bytes) -> bool:
    """Verifies a 64-byte BIP-340 Schnorr signature using native libsecp256k1."""
    if len(msg_32) != 32 or len(pubkey_xonly_32) != 32 or len(sig_64) != 64:
        return False

    lib = coincurve._libsecp256k1.lib
    ffi = coincurve._libsecp256k1.ffi
    ctx = coincurve.context.GLOBAL_CONTEXT.ctx

    xonly_pk = ffi.new("secp256k1_xonly_pubkey *")
    ret = lib.secp256k1_xonly_pubkey_parse(ctx, xonly_pk, pubkey_xonly_32)
    if ret != 1:
        return False

    valid = lib.secp256k1_schnorrsig_verify(ctx, sig_64, msg_32, 32, xonly_pk)
    return valid == 1


# ==============================================================================
# NIP-44 (Version 2) Encrypted Payloads
# ==============================================================================

def compute_conversation_key(sk_bytes: bytes, pk_xonly_bytes: bytes) -> bytes:
    """
    Computes NIP-44 v2 conversation key via Secp256k1 ECDH and HKDF-Extract.
    conversation_key = HKDF-Extract(salt="nip44-v2", ikm=S_x)
    """
    if len(sk_bytes) != 32 or len(pk_xonly_bytes) != 32:
        raise ValueError("Invalid key lengths for ECDH")

    # Compressed point representation with even parity 0x02
    pk_point = b"\x02" + pk_xonly_bytes
    shared_pt = coincurve.PublicKey(pk_point).multiply(sk_bytes).format(compressed=False)
    # shared point x-coordinate (32 bytes)
    shared_x = shared_pt[1:33]

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"nip44-v2", info=None)
    return hkdf.derive(shared_x)


def _calc_padded_len(length: int) -> int:
    """NIP-44 power-of-two padding calculation."""
    if length <= 32:
        return 32
    next_power = 1 << ((length - 1).bit_length())
    chunk = 32 if next_power <= 256 else (next_power // 8)
    return chunk * ((length + chunk - 1) // chunk)


def nip44_encrypt(conv_key: bytes, plaintext: str) -> str:
    """
    Encrypts a plaintext string according to NIP-44 v2 specifications.
    Returns standard Base64-encoded string prefixed with version 0x02.
    """
    nonce = os.urandom(32)
    expand = HKDFExpand(algorithm=hashes.SHA256(), length=76, info=nonce)
    keys = expand.derive(conv_key)
    k_e = keys[0:32]
    chacha_nonce = keys[32:44]
    k_auth = keys[44:76]

    pt_bytes = plaintext.encode("utf-8")
    if len(pt_bytes) > 65535:
        raise ValueError("Plaintext exceeds maximum NIP-44 limit (65535 bytes)")

    padded_len = _calc_padded_len(len(pt_bytes))
    padded_payload = (
        len(pt_bytes).to_bytes(2, "big")
        + pt_bytes
        + b"\x00" * (padded_len - len(pt_bytes))
    )

    # ChaCha20 with 4-byte zero counter (little-endian) + 12-byte nonce
    nonce16 = b"\x00\x00\x00\x00" + chacha_nonce
    cipher = Cipher(algorithms.ChaCha20(k_e, nonce16), mode=None)
    ciphertext = cipher.encryptor().update(padded_payload)

    # HMAC-SHA256(k_auth, nonce + ciphertext)
    mac = py_hmac.new(k_auth, nonce + ciphertext, hashlib.sha256).digest()

    raw_output = b"\x02" + nonce + ciphertext + mac
    return base64.b64encode(raw_output).decode("ascii")


def nip44_decrypt(conv_key: bytes, b64_payload: str) -> str:
    """
    Decrypts a NIP-44 v2 Base64 payload string and verifies HMAC authentication.
    """
    raw = base64.b64decode(b64_payload)
    if len(raw) < 1 + 32 + 32 + 32:  # version + nonce + min_padded_ct + mac
        raise ValueError("Ciphertext too short for NIP-44 v2")
    if raw[0] != 2:
        raise ValueError(f"Unsupported NIP-44 version: {raw[0]}")

    nonce = raw[1:33]
    mac = raw[-32:]
    ciphertext = raw[33:-32]

    expand = HKDFExpand(algorithm=hashes.SHA256(), length=76, info=nonce)
    keys = expand.derive(conv_key)
    k_e = keys[0:32]
    chacha_nonce = keys[32:44]
    k_auth = keys[44:76]

    expected_mac = py_hmac.new(k_auth, nonce + ciphertext, hashlib.sha256).digest()
    if not py_hmac.compare_digest(mac, expected_mac):
        raise ValueError("Invalid NIP-44 authentication tag (MAC mismatch)")

    nonce16 = b"\x00\x00\x00\x00" + chacha_nonce
    cipher = Cipher(algorithms.ChaCha20(k_e, nonce16), mode=None)
    decrypted_padded = cipher.decryptor().update(ciphertext)

    unpadded_len = int.from_bytes(decrypted_padded[:2], "big")
    if unpadded_len > len(decrypted_padded) - 2:
        raise ValueError("Corrupted length prefix in decrypted payload")

    pt_bytes = decrypted_padded[2 : 2 + unpadded_len]
    return pt_bytes.decode("utf-8")


# ==============================================================================
# Nostr Event Models (NIP-01)
# ==============================================================================

class NostrEvent(BaseModel):
    """NIP-01 standard Nostr Event."""
    id: str = ""
    pubkey: str
    created_at: int
    kind: int
    tags: List[List[str]] = Field(default_factory=list)
    content: str
    sig: str = ""

    def serialize(self) -> str:
        """Serializes event for ID computation according to NIP-01."""
        data = [
            0,
            self.pubkey.lower(),
            self.created_at,
            self.kind,
            self.tags,
            self.content,
        ]
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)

    def compute_id(self) -> str:
        """Computes SHA-256 event ID."""
        canonical_bytes = self.serialize().encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()

    def sign(self, privkey_bytes: bytes) -> None:
        """Computes ID and generates BIP-340 Schnorr signature."""
        self.id = self.compute_id()
        msg_hash = bytes.fromhex(self.id)
        sig_bytes = schnorr_sign(msg_hash, privkey_bytes)
        self.sig = sig_bytes.hex()

    def verify(self) -> bool:
        """Verifies event ID and BIP-340 signature."""
        if self.compute_id() != self.id:
            return False
        try:
            msg_hash = bytes.fromhex(self.id)
            pubkey_bytes = bytes.fromhex(self.pubkey)
            sig_bytes = bytes.fromhex(self.sig)
            return schnorr_verify(msg_hash, pubkey_bytes, sig_bytes)
        except Exception:
            return False


# ==============================================================================
# NIP-90 DVM Job Models & Helpers
# ==============================================================================

class DVMJobRequest(BaseModel):
    """Parsed NIP-90 Kind 5000 Job Request."""
    event_id: str
    requester_pubkey: str
    prompt: str
    cashu_token: Optional[str] = None
    model: Optional[str] = None
    bid_amount_msats: Optional[int] = None
    relays: List[str] = Field(default_factory=list)
    is_targeted: bool = False
    targeted_pubkey: Optional[str] = None


def parse_job_request(event: NostrEvent, worker_pubkey: str) -> Optional[DVMJobRequest]:
    """
    Parses a Kind 5000 event into a structured DVMJobRequest.
    Extracts prompt input, cashu tokens, models, and relays.
    """
    if event.kind != 5000:
        return None

    prompt = ""
    cashu_token = None
    model = None
    bid_amount_msats = None
    relays: List[str] = []
    is_targeted = False
    targeted_pubkey = None

    # Scan tags
    for tag in event.tags:
        if not tag:
            continue
        tag_name = tag[0]

        if tag_name == "i":
            if len(tag) > 1:
                val = tag[1]
                type_hint = tag[2] if len(tag) > 2 else "text"
                if type_hint == "cashu" or val.startswith("cashuA"):
                    cashu_token = val
                else:
                    if not prompt:
                        prompt = val
        elif tag_name == "cashu" and len(tag) > 1:
            cashu_token = tag[1]
        elif tag_name == "param" and len(tag) > 2:
            param_key = tag[1].lower()
            param_val = tag[2]
            if param_key == "model":
                model = param_val
            elif param_key == "cashu":
                cashu_token = param_val
        elif tag_name == "p" and len(tag) > 1:
            targeted_pubkey = tag[1].lower()
            if targeted_pubkey == worker_pubkey.lower():
                is_targeted = True
        elif tag_name == "bid" and len(tag) > 1:
            try:
                bid_amount_msats = int(tag[1])
            except ValueError:
                pass
        elif tag_name == "relays":
            relays.extend([r for r in tag[1:] if r.startswith("ws")])

    # If prompt not in 'i' tag, check event content
    if not prompt and event.content:
        prompt = event.content

    # If cashu token not in tags, check if content contains a cashuA token
    if not cashu_token:
        match = re.search(r"cashuA[A-Za-z0-9_-]+={0,2}", event.content or "")
        if match:
            cashu_token = match.group(0)

    return DVMJobRequest(
        event_id=event.id,
        requester_pubkey=event.pubkey,
        prompt=prompt,
        cashu_token=cashu_token,
        model=model,
        bid_amount_msats=bid_amount_msats,
        relays=relays,
        is_targeted=is_targeted,
        targeted_pubkey=targeted_pubkey,
    )


def create_job_feedback_event(
    worker_pubkey: str,
    worker_privkey_bytes: bytes,
    request_event_id: str,
    customer_pubkey: str,
    status: str,  # "processing", "payment-required", "error", "success"
    message: str = "",
    extra_tags: Optional[List[List[str]]] = None,
) -> NostrEvent:
    """Creates a signed NIP-90 Kind 7000 feedback event."""
    tags = [
        ["e", request_event_id],
        ["p", customer_pubkey],
        ["status", status],
    ]
    if extra_tags:
        tags.extend(extra_tags)

    event = NostrEvent(
        pubkey=worker_pubkey,
        created_at=int(time.time()),
        kind=7000,
        tags=tags,
        content=message,
    )
    event.sign(worker_privkey_bytes)
    return event


def create_job_result_event(
    worker_pubkey: str,
    worker_privkey_bytes: bytes,
    request_event_id: str,
    customer_pubkey: str,
    prompt: str,
    result_text: str,
    settled_sats: int,
    encrypt_response: bool = True,
) -> NostrEvent:
    """Creates a signed NIP-90 Kind 6000 result event, encrypted with NIP-44 v2."""
    tags = [
        ["e", request_event_id],
        ["p", customer_pubkey],
        ["i", prompt],
        ["amount", str(settled_sats)],
    ]

    final_content = result_text
    if encrypt_response:
        conv_key = compute_conversation_key(worker_privkey_bytes, bytes.fromhex(customer_pubkey))
        final_content = nip44_encrypt(conv_key, result_text)
        tags.append(["encrypted"])

    event = NostrEvent(
        pubkey=worker_pubkey,
        created_at=int(time.time()),
        kind=6000,
        tags=tags,
        content=final_content,
    )
    event.sign(worker_privkey_bytes)
    return event


# ==============================================================================
# Resilient Relay Pool Manager
# ==============================================================================

class NostrRelayPool:
    """
    Manages concurrent WebSocket connections to multiple Nostr relays.
    Includes auto-reconnection with exponential backoff and deduplication.
    """

    def __init__(
        self,
        relays: List[str],
        on_event_callback: Callable[[NostrEvent], Coroutine[Any, Any, None]],
    ):
        self.relays = list(set(relays))
        self.on_event_callback = on_event_callback
        self._running = False
        self._seen_event_ids: Set[str] = set()
        self._seen_ids_order: List[str] = []
        self._max_seen_cache = 10000
        self._connections: Dict[str, websockets.ClientConnection] = {}
        self._tasks: List[asyncio.Task] = []

    def _mark_seen(self, event_id: str) -> bool:
        """Returns True if already seen, else registers and returns False."""
        if event_id in self._seen_event_ids:
            return True
        self._seen_event_ids.add(event_id)
        self._seen_ids_order.append(event_id)
        if len(self._seen_ids_order) > self._max_seen_cache:
            evicted = self._seen_ids_order.pop(0)
            self._seen_event_ids.discard(evicted)
        return False

    async def start(self) -> None:
        """Starts connection loops to all configured relays."""
        self._running = True
        for relay_url in self.relays:
            task = asyncio.create_task(self._relay_loop(relay_url))
            self._tasks.append(task)
        logger.info("Relay pool started across %d relays: %s", len(self.relays), self.relays)

    async def stop(self) -> None:
        """Gracefully disconnects from all relays."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        for url, ws in list(self._connections.items()):
            try:
                await ws.close()
            except Exception:
                pass
        self._connections.clear()
        logger.info("Relay pool stopped.")

    async def broadcast_event(self, event: NostrEvent) -> None:
        """Broadcasts a signed event to all connected relays."""
        msg = json.dumps(["EVENT", event.model_dump()])
        sent_count = 0
        for url, ws in list(self._connections.items()):
            try:
                await ws.send(msg)
                sent_count += 1
            except Exception as e:
                logger.warning("Failed to broadcast to %s: %s", url, e)
        logger.info("Broadcasted event %s (kind %d) to %d relays", event.id[:8], event.kind, sent_count)

    async def _relay_loop(self, relay_url: str) -> None:
        """Persistent connection loop with exponential backoff for a single relay."""
        backoff = 1.0
        max_backoff = 60.0

        while self._running:
            try:
                logger.info("Connecting to relay: %s", relay_url)
                async with websockets.connect(
                    relay_url,
                    ping_interval=20,
                    ping_timeout=15,
                    close_timeout=5,
                ) as ws:
                    self._connections[relay_url] = ws
                    backoff = 1.0
                    logger.info("Connected to relay: %s", relay_url)

                    # Subscribe to Kind 5000 DVM job requests
                    sub_id = f"pv_sub_{secrets.token_hex(4)}"
                    # Query jobs from the last 15 minutes to pick up recent pending jobs
                    since_ts = int(time.time()) - 900
                    sub_msg = json.dumps([
                        "REQ",
                        sub_id,
                        {"kinds": [5000], "since": since_ts},
                    ])
                    await ws.send(sub_msg)

                    async for message in ws:
                        if not self._running:
                            break
                        await self._handle_relay_message(relay_url, message)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("Relay connection error on %s: %s", relay_url, e)
            finally:
                self._connections.pop(relay_url, None)

            if self._running:
                logger.info("Reconnecting to %s in %.1f seconds...", relay_url, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2.0, max_backoff)

    async def _handle_relay_message(self, relay_url: str, message: str) -> None:
        """Parses and dispatches inbound messages from a relay."""
        try:
            data = json.loads(message)
            if not isinstance(data, list) or len(data) < 2:
                return

            msg_type = data[0]
            if msg_type == "EVENT" and len(data) >= 3:
                event_dict = data[2]
                event = NostrEvent.model_validate(event_dict)

                # Deduplicate across relays
                if self._mark_seen(event.id):
                    return

                # Verify signature and ID
                if not event.verify():
                    logger.warning("Rejected event %s with invalid signature", event.id[:8])
                    return

                # Dispatch to worker callback asynchronously
                asyncio.create_task(self.on_event_callback(event))

            elif msg_type == "NOTICE":
                logger.info("Notice from %s: %s", relay_url, data[1])
            elif msg_type == "OK":
                logger.debug("OK from %s: %s", relay_url, data[1:])
        except Exception as e:
            logger.debug("Error processing message from %s: %s", relay_url, e)
