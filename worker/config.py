"""
PrivaVend Configuration Manager
Loads settings from environment variables and .env file using Pydantic Settings.
Manages Nostr cryptographic identity (ephemeral or persistent).
"""

import os
import secrets
import logging
from typing import List, Optional
import coincurve
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("privavend.config")


class Settings(BaseSettings):
    """PrivaVend daemon application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Nostr Protocol Settings ---
    nostr_private_key: str = Field(
        default="",
        description="Hex-encoded 32-byte private key. If empty, an ephemeral key is generated.",
    )
    nostr_relays: str = Field(
        default="wss://relay.damus.io,wss://nos.lol,wss://relay.primal.net",
        description="Comma-separated WebSocket relay URLs.",
    )
    require_targeted_pubkey: bool = Field(
        default=False,
        description="If True, only processes NIP-90 jobs tagged with this worker's 'p' pubkey.",
    )

    # --- Cashu Settlement Settings ---
    cashu_mint_url: str = Field(
        default="https://mint.minibits.cash/Bitcoin",
        description="Default Cashu Mint URL for verification and swap.",
    )
    cashu_min_fee_sats: int = Field(
        default=1,
        description="Minimum required fee in satoshis to process a job request.",
    )
    cashu_auto_swap: bool = Field(
        default=True,
        description="Whether to atomically swap received ecash proofs at the mint upon receipt.",
    )
    cashu_allow_mock_fallback: bool = Field(
        default=False,
        description="Allow offline simulation of Cashu settlement during local testing.",
    )

    # --- AI Inference Settings ---
    ai_backend: str = Field(
        default="ollama",
        description="AI engine backend: 'ollama', 'openai_compatible', or 'mock'.",
    )
    ai_model: str = Field(
        default="llama3",
        description="Model name to invoke for text generation.",
    )
    ollama_base_url: str = Field(
        default="http://127.0.0.1:11434",
        description="Local Ollama HTTP endpoint.",
    )
    openai_api_key: Optional[str] = Field(
        default=None,
        description="API key for external LLM fallback provider.",
    )
    openai_base_url: str = Field(
        default="https://api.together.xyz/v1",
        description="Base URL for OpenAI-compatible inference endpoints.",
    )

    # --- Limits & Operational Limits ---
    max_prompt_chars: int = Field(
        default=8192,
        description="Upper limit on characters in user prompt to prevent memory exhaustion.",
    )
    inference_timeout_secs: int = Field(
        default=60,
        description="Maximum seconds before an AI inference job times out.",
    )
    max_concurrent_jobs: int = Field(
        default=10,
        description="Maximum concurrent AI jobs handled simultaneously.",
    )
    log_level: str = Field(
        default="INFO",
        description="Daemon logging level: DEBUG, INFO, WARNING, ERROR.",
    )

    # Derived identity attributes (populated on initialization)
    _privkey_bytes: bytes = b""
    _pubkey_hex: str = ""

    def initialize_identity(self) -> None:
        """Derives or generates the Nostr secp256k1 keypair."""
        clean_key = self.nostr_private_key.strip()
        if clean_key.startswith("nsec"):
            # Handle bech32 nsec if provided
            from worker.core.nostr import bech32_decode_nsec
            clean_key = bech32_decode_nsec(clean_key)

        if clean_key:
            try:
                sk_bytes = bytes.fromhex(clean_key)
                if len(sk_bytes) != 32:
                    raise ValueError("Nostr private key must be exactly 32 bytes (64 hex characters)")
                self._privkey_bytes = sk_bytes
            except ValueError as e:
                logger.error("Invalid NOSTR_PRIVATE_KEY provided in config: %s", e)
                raise
        else:
            # Ephemeral key generation
            self._privkey_bytes = secrets.token_bytes(32)
            logger.info("No NOSTR_PRIVATE_KEY provided. Generated ephemeral session key.")

        # Calculate x-only public key
        priv = coincurve.PrivateKey(self._privkey_bytes)
        compressed_pub = priv.public_key.format(compressed=True)
        # BIP-340 x-only public key is 32 bytes (skipping 0x02/0x03 parity byte)
        self._pubkey_hex = compressed_pub[1:].hex()

    @property
    def private_key_hex(self) -> str:
        return self._privkey_bytes.hex()

    @property
    def private_key_bytes(self) -> bytes:
        return self._privkey_bytes

    @property
    def public_key_hex(self) -> str:
        return self._pubkey_hex

    @property
    def relay_list(self) -> List[str]:
        """Returns clean list of relay URLs."""
        return [r.strip() for r in self.nostr_relays.split(",") if r.strip()]


# Global settings singleton loader
_settings_instance: Optional[Settings] = None


def get_settings() -> Settings:
    """Returns the initialized singleton settings instance."""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = Settings()
        _settings_instance.initialize_identity()
    return _settings_instance
