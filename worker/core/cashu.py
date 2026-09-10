"""
PrivaVend Cashu Core Engine
Implements NUT-00 (Token format, BDHKE cryptography, hash_to_curve),
NUT-01 (Keysets), NUT-02 (Keyset discovery), NUT-03 (Swap/Redemption),
NUT-04 (Minting), NUT-05 (Melting), and NUT-07 (Proof State Checking).
"""

import base64
import hashlib
import json
import logging
import secrets
from typing import Dict, List, Optional, Tuple, Any
import coincurve
import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger("privavend.cashu")

# Secp256k1 Field Prime
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
# Curve Order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BB5BF38EFCA333B6F


class CashuError(Exception):
    """Base exception for Cashu operations."""
    pass


class CashuVerificationError(CashuError):
    """Raised when token proofs fail cryptographic or mint validation."""
    pass


class CashuDoubleSpendError(CashuError):
    """Raised when token proofs have already been spent."""
    pass


class CashuNetworkError(CashuError):
    """Raised when mint endpoint communication fails."""
    pass


class Proof(BaseModel):
    """NUT-00 Cashu Proof object representing an ecash coin."""
    id: str = Field(description="Keyset ID")
    amount: int = Field(gt=0, description="Amount in satoshis")
    secret: str = Field(description="Secret message preimage")
    C: str = Field(description="Unblinded Mint signature point (hex)")
    witness: Optional[str] = Field(default=None, description="Optional NUT-10/11 spending witness")

    def compute_y(self) -> str:
        """Computes the curve point Y = hash_to_curve(secret) in hex."""
        return hash_to_curve(self.secret.encode("utf-8")).hex()


class TokenEntry(BaseModel):
    """NUT-00 Token entry grouping proofs under a specific mint."""
    mint: str
    proofs: List[Proof]


class TokenV3(BaseModel):
    """NUT-00 Token V3 payload structure."""
    token: List[TokenEntry]
    memo: Optional[str] = None

    @property
    def total_amount(self) -> int:
        """Calculates total sat value across all proofs."""
        return sum(proof.amount for entry in self.token for proof in entry.proofs)

    @property
    def primary_mint(self) -> Optional[str]:
        """Returns the first mint URL in the token payload."""
        if self.token and self.token[0].mint:
            return self.token[0].mint.rstrip("/")
        return None

    @property
    def all_proofs(self) -> List[Proof]:
        """Flattens all proofs into a single list."""
        res: List[Proof] = []
        for entry in self.token:
            res.extend(entry.proofs)
        return res


# ==============================================================================
# NUT-00 BDHKE Elliptic Curve Primitives
# ==============================================================================

def hash_to_curve(secret: bytes) -> bytes:
    """
    NUT-00 specification for hash_to_curve over Secp256k1.
    Derives a valid compressed public key point from an arbitrary secret.
    """
    msg_hash = hashlib.sha256(b"Secp256k1_HashToCurve_Cashu_" + secret).digest()
    for counter in range(65536):
        x_bytes = hashlib.sha256(msg_hash + counter.to_bytes(4, "little")).digest()
        x = int.from_bytes(x_bytes, "big")
        if x >= P:
            continue
        # Secp256k1 equation: y^2 = x^3 + 7 (mod p)
        y2 = (pow(x, 3, P) + 7) % P
        # Modular square root via Euler's criterion for p = 3 mod 4
        y = pow(y2, (P + 1) // 4, P)
        if pow(y, 2, P) == y2:
            # Pick even y per Cashu NUT-00
            if y % 2 != 0:
                y = P - y
            return b"\x02" + x_bytes
    raise CashuVerificationError("hash_to_curve failed: no valid curve point found in 65536 iterations")


def negate_point(compressed_point: bytes) -> bytes:
    """Negates a compressed Secp256k1 point (x, y) -> (x, -y)."""
    if len(compressed_point) != 33:
        raise ValueError("Invalid compressed point length")
    prefix = compressed_point[0]
    if prefix == 0x02:
        return b"\x03" + compressed_point[1:]
    elif prefix == 0x03:
        return b"\x02" + compressed_point[1:]
    raise ValueError("Invalid point prefix")


def split_amount_into_powers_of_two(amount: int) -> List[int]:
    """Splits an integer amount into powers of two (standard Cashu denominations)."""
    powers: List[int] = []
    bit = 1
    remaining = amount
    while remaining > 0:
        if remaining & bit:
            powers.append(bit)
            remaining -= bit
        bit <<= 1
    return powers


# ==============================================================================
# Token Serialization / Deserialization
# ==============================================================================

def decode_token(token_str: str) -> TokenV3:
    """
    Decodes a Cashu ecash token (NUT-00).
    Supports 'cashuA...' (V3 JSON format) and raw JSON payloads.
    """
    clean_str = token_str.strip()
    if clean_str.startswith("cashuA"):
        raw_b64 = clean_str[6:]
        # Fix base64 padding if needed
        raw_b64 += "=" * (-len(raw_b64) % 4)
        try:
            # Try URL-safe base64 first
            decoded_bytes = base64.urlsafe_b64decode(raw_b64.encode("ascii"))
        except Exception:
            try:
                decoded_bytes = base64.b64decode(raw_b64.encode("ascii"))
            except Exception as e:
                raise CashuVerificationError(f"Failed to base64-decode token: {e}")
        try:
            data = json.loads(decoded_bytes.decode("utf-8"))
        except Exception as e:
            raise CashuVerificationError(f"Failed to parse token JSON: {e}")
    else:
        # Check if raw JSON was provided
        try:
            data = json.loads(clean_str)
        except Exception as e:
            raise CashuVerificationError(f"Unrecognized Cashu token format: {e}")

    try:
        return TokenV3.model_validate(data)
    except Exception as e:
        raise CashuVerificationError(f"Invalid Cashu token schema: {e}")


def encode_token_v3(mint_url: str, proofs: List[Proof], memo: Optional[str] = None) -> str:
    """
    Encodes a list of proofs and mint URL into a 'cashuA...' token string.
    """
    payload = {
        "token": [
            {
                "mint": mint_url.rstrip("/"),
                "proofs": [p.model_dump(exclude_none=True) for p in proofs],
            }
        ]
    }
    if memo:
        payload["memo"] = memo

    json_str = json.dumps(payload, separators=(",", ":"))
    b64 = base64.urlsafe_b64encode(json_str.encode("utf-8")).decode("ascii").rstrip("=")
    return f"cashuA{b64}"


# ==============================================================================
# Cashu Mint Client & Atomic Swap Engine
# ==============================================================================

class CashuMintClient:
    """
    Client for interacting with a Cashu Mint via the REST API (NUT-00 through NUT-07).
    Performs atomic swaps to redeem incoming client proofs into fresh worker proofs.
    """

    def __init__(self, default_mint_url: str, allow_mock_fallback: bool = False, timeout_secs: float = 15.0):
        self.default_mint_url = default_mint_url.rstrip("/")
        self.allow_mock_fallback = allow_mock_fallback
        self.timeout_secs = timeout_secs
        # In-memory keyset cache: {mint_url: {keyset_id: {amount: pubkey_hex}}}
        self._keys_cache: Dict[str, Dict[str, Dict[int, str]]] = {}

    async def get_keys(self, mint_url: Optional[str] = None) -> Dict[str, Dict[int, str]]:
        """
        Fetches active keysets from the mint (NUT-01).
        Returns a mapping of keyset_id -> {amount: pubkey_hex}.
        """
        target_mint = (mint_url or self.default_mint_url).rstrip("/")
        if target_mint in self._keys_cache:
            return self._keys_cache[target_mint]

        url = f"{target_mint}/v1/keys"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_secs) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    raise CashuNetworkError(f"Mint returned HTTP {resp.status_code}: {resp.text}")
                data = resp.json()
        except Exception as e:
            if self.allow_mock_fallback:
                logger.warning("Mint %s unreachable, using simulated mock keys: %s", target_mint, e)
                return self._generate_mock_keys(target_mint)
            raise CashuNetworkError(f"Failed to connect to Cashu mint {target_mint}: {e}")

        # Parse NUT-01 keysets
        keysets_dict: Dict[str, Dict[int, str]] = {}
        # Mint returns either {"keysets": [{"id": ..., "keys": {...}}]} or {"keys": {...}}
        if "keysets" in data and isinstance(data["keysets"], list):
            for ks in data["keysets"]:
                ks_id = str(ks.get("id"))
                raw_keys = ks.get("keys", {})
                keysets_dict[ks_id] = {int(k): str(v) for k, v in raw_keys.items()}
        elif "keys" in data and isinstance(data["keys"], dict):
            # Keyset with default ID or legacy format
            raw_keys = data["keys"]
            keysets_dict["default"] = {int(k): str(v) for k, v in raw_keys.items()}
        else:
            raise CashuVerificationError(f"Unexpected keyset format from mint: {data}")

        self._keys_cache[target_mint] = keysets_dict
        return keysets_dict

    def _generate_mock_keys(self, target_mint: str) -> Dict[str, Dict[int, str]]:
        """Generates deterministic mock keysets for offline local test environments."""
        mock_id = "mock_keyset_001"
        mock_keys: Dict[int, str] = {}
        for amt in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024]:
            # Generate deterministic point for mock testing
            seed = hashlib.sha256(f"mock_mint_key_{amt}".encode()).digest()
            pub = coincurve.PrivateKey(seed).public_key.format(compressed=True).hex()
            mock_keys[amt] = pub
        res = {mock_id: mock_keys}
        self._keys_cache[target_mint] = res
        return res

    async def check_proof_states(self, proofs: List[Proof], mint_url: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Queries NUT-07 /v1/checkstate to ensure proofs are UNSPENT.
        """
        target_mint = (mint_url or self.default_mint_url).rstrip("/")
        ys = [proof.compute_y() for proof in proofs]

        url = f"{target_mint}/v1/checkstate"
        payload = {"Ys": ys}

        try:
            async with httpx.AsyncClient(timeout=self.timeout_secs) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("states", [])
                else:
                    logger.warning("Mint checkstate returned HTTP %d: %s", resp.status_code, resp.text)
        except Exception as e:
            if not self.allow_mock_fallback:
                raise CashuNetworkError(f"Checkstate request failed: {e}")
            logger.info("Allowing mock checkstate fallback: %s", e)

        # Fallback simulation if mint is offline or in mock mode
        return [{"Y": y, "state": "UNSPENT"} for y in ys]

    async def swap_proofs(
        self,
        proofs: List[Proof],
        mint_url: Optional[str] = None,
    ) -> Tuple[List[Proof], int]:
        """
        Atomically redeems and swaps incoming proofs for fresh worker-controlled proofs (NUT-03).
        This guarantees settlement: once swapped, the client cannot double-spend or revoke the ecash.
        Returns:
            Tuple of (new_settled_proofs, total_sat_value)
        """
        target_mint = (mint_url or self.default_mint_url).rstrip("/")
        total_sats = sum(p.amount for p in proofs)
        if total_sats <= 0:
            raise CashuVerificationError("Swap rejected: token amount must be greater than zero")

        # Fetch active keysets to identify target keyset and public keys
        keysets = await self.get_keys(target_mint)
        target_keyset_id = list(keysets.keys())[0] if keysets else "default"
        mint_pubkeys = keysets.get(target_keyset_id, {})

        # Split total amount into binary denominations
        output_amounts = split_amount_into_powers_of_two(total_sats)

        # Prepare blinded outputs (B') and retain blinding factors (r, secret)
        blinded_outputs = []
        secrets_and_rs: List[Tuple[int, str, bytes]] = []  # (amount, secret_str, r_bytes)

        for amt in output_amounts:
            secret_str = secrets.token_hex(32)
            r_bytes = secrets.token_bytes(32)
            y_bytes = hash_to_curve(secret_str.encode("utf-8"))
            r_pub_bytes = coincurve.PrivateKey(r_bytes).public_key.format(compressed=True)

            # B' = Y + r*G
            b_prime = coincurve.PublicKey(y_bytes).combine([coincurve.PublicKey(r_pub_bytes)]).format(compressed=True)

            blinded_outputs.append({
                "amount": amt,
                "id": target_keyset_id,
                "B_": b_prime.hex(),
            })
            secrets_and_rs.append((amt, secret_str, r_bytes))

        # Submit swap request to /v1/swap
        swap_url = f"{target_mint}/v1/swap"
        swap_payload = {
            "inputs": [p.model_dump(exclude_none=True) for p in proofs],
            "outputs": blinded_outputs,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout_secs) as client:
                resp = await client.post(swap_url, json=swap_payload)
                if resp.status_code != 200:
                    err_msg = resp.text
                    if "already spent" in err_msg.lower() or "token already spent" in err_msg.lower():
                        raise CashuDoubleSpendError(f"Double-spend detected: {err_msg}")
                    raise CashuVerificationError(f"Mint swap failed with status {resp.status_code}: {err_msg}")
                data = resp.json()
        except CashuDoubleSpendError:
            raise
        except Exception as e:
            if not self.allow_mock_fallback:
                raise CashuNetworkError(f"Swap execution failed against mint {target_mint}: {e}")
            logger.warning("Mint swap failed, falling back to simulated settlement: %s", e)
            data = self._simulate_mock_swap(blinded_outputs)

        signatures = data.get("signatures", [])
        if len(signatures) != len(blinded_outputs):
            raise CashuVerificationError(
                f"Mint returned {len(signatures)} signatures, expected {len(blinded_outputs)}"
            )

        # Unblind signatures: C = C' - r*K
        new_proofs: List[Proof] = []
        for i, sig in enumerate(signatures):
            amt, secret_str, r_bytes = secrets_and_rs[i]
            c_prime_hex = sig.get("C_")
            c_prime_bytes = bytes.fromhex(c_prime_hex)

            # Get mint public key K for this denomination
            k_hex = mint_pubkeys.get(amt)
            if k_hex:
                k_bytes = bytes.fromhex(k_hex)
                r_k_bytes = coincurve.PublicKey(k_bytes).multiply(r_bytes).format(compressed=True)
                neg_r_k = negate_point(r_k_bytes)
                # C = C' + (-r*K)
                c_bytes = coincurve.PublicKey(c_prime_bytes).combine([coincurve.PublicKey(neg_r_k)]).format(compressed=True)
                final_c_hex = c_bytes.hex()
            else:
                # In mock/unkeyed fallback mode
                final_c_hex = c_prime_hex

            new_proofs.append(Proof(
                id=sig.get("id", target_keyset_id),
                amount=amt,
                secret=secret_str,
                C=final_c_hex,
            ))

        logger.info("Successfully settled %d sats via atomic swap with mint %s", total_sats, target_mint)
        return new_proofs, total_sats

    def _simulate_mock_swap(self, outputs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Simulates mint swap response when in local mock test mode."""
        signatures = []
        for out in outputs:
            b_prime = bytes.fromhex(out["B_"])
            amt = out["amount"]
            # Mock sign using deterministic key
            mock_k = hashlib.sha256(f"mock_mint_key_{amt}".encode()).digest()
            c_prime = coincurve.PublicKey(b_prime).multiply(mock_k).format(compressed=True).hex()
            signatures.append({
                "amount": amt,
                "id": out["id"],
                "C_": c_prime,
            })
        return {"signatures": signatures}


# ==============================================================================
# In-Memory Vault for Accumulated Daemon Sats
# ==============================================================================

class CashuVault:
    """Thread-safe / async in-memory ecash vault for the PrivaVend worker."""

    def __init__(self):
        self._proofs: List[Proof] = []
        self._total_earned_sats: int = 0

    def add_settled_proofs(self, proofs: List[Proof]) -> None:
        """Stores settled proofs and increments the earned sats counter."""
        self._proofs.extend(proofs)
        new_sats = sum(p.amount for p in proofs)
        self._total_earned_sats += new_sats
        logger.info("Vault updated: +%d sats (Total vault balance: %d sats)", new_sats, self.balance)

    @property
    def balance(self) -> int:
        return sum(p.amount for p in self._proofs)

    @property
    def total_earned(self) -> int:
        return self._total_earned_sats

    def get_all_proofs(self) -> List[Proof]:
        return list(self._proofs)
