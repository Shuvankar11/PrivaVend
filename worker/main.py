"""
PrivaVend Daemon Main Runner
Autonomous, zero-trace AI Data Vending Machine (DVM) operating over Nostr (NIP-90)
and settled atomically off-chain via Cashu (NUT-00 to NUT-07) Chaumian Ecash.
"""

import asyncio
import logging
import signal
import sys
import time
from typing import Optional
from worker.config import Settings, get_settings
from worker.core.ai_engine import AIEngine, AIInferenceError
from worker.core.cashu import (
    CashuDoubleSpendError,
    CashuMintClient,
    CashuVault,
    CashuVerificationError,
    decode_token,
)
from worker.core.nostr import (
    DVMJobRequest,
    NostrEvent,
    NostrRelayPool,
    create_job_feedback_event,
    create_job_result_event,
    parse_job_request,
    pubkey_to_npub,
)

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("privavend.daemon")


class PrivaVendDaemon:
    """Core daemon managing relay subscriptions, Cashu settlement, and AI execution."""

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.vault = CashuVault()
        self.mint_client = CashuMintClient(
            default_mint_url=self.settings.cashu_mint_url,
            allow_mock_fallback=self.settings.cashu_allow_mock_fallback,
            timeout_secs=15.0,
        )
        self.ai_engine = AIEngine(
            backend=self.settings.ai_backend,
            default_model=self.settings.ai_model,
            ollama_base_url=self.settings.ollama_base_url,
            openai_api_key=self.settings.openai_api_key,
            openai_base_url=self.settings.openai_base_url,
            timeout_secs=float(self.settings.inference_timeout_secs),
            max_prompt_chars=self.settings.max_prompt_chars,
        )
        self.relay_pool = NostrRelayPool(
            relays=self.settings.relay_list,
            on_event_callback=self._handle_inbound_event,
        )
        self._semaphore = asyncio.Semaphore(self.settings.max_concurrent_jobs)
        self._active_tasks: set[asyncio.Task] = set()
        self._shutdown_event = asyncio.Event()

    async def _handle_inbound_event(self, event: NostrEvent) -> None:
        """Processes incoming Nostr events from the relay pool."""
        if event.kind != 5000:
            return

        task = asyncio.create_task(self._process_job_wrapper(event))
        self._active_tasks.add(task)
        task.add_done_callback(self._active_tasks.discard)

    async def _process_job_wrapper(self, event: NostrEvent) -> None:
        """Limits concurrency and isolates task failures."""
        async with self._semaphore:
            try:
                await self._process_job(event)
            except Exception as e:
                logger.error("Unhandled error processing job event %s: %s", event.id[:8], e, exc_info=True)

    async def _process_job(self, event: NostrEvent) -> None:
        """
        End-to-end NIP-90 lifecycle:
        1. Parse request
        2. Verify Cashu token
        3. Atomically redeem/swap ecash at mint
        4. Broadcast feedback (processing)
        5. Run AI inference
        6. Encrypt with NIP-44 v2 and publish Kind 6000 result
        """
        job = parse_job_request(event, self.settings.public_key_hex)
        if not job:
            return

        # Target filtering check
        if self.settings.require_targeted_pubkey and not job.is_targeted:
            logger.debug("Skipping unaddressed job %s (daemon requires targeted pubkey)", event.id[:8])
            return

        logger.info(
            "Received Job %s from %s... | Prompt: '%s' | Model: %s",
            job.event_id[:8],
            job.requester_pubkey[:8],
            job.prompt[:60].replace("\n", " "),
            job.model or self.settings.ai_model,
        )

        # 1. Verify Ecash Token Presence
        if not job.cashu_token:
            logger.warning("Job %s rejected: No Cashu token provided", job.event_id[:8])
            fb = create_job_feedback_event(
                worker_pubkey=self.settings.public_key_hex,
                worker_privkey_bytes=self.settings.private_key_bytes,
                request_event_id=job.event_id,
                customer_pubkey=job.requester_pubkey,
                status="payment-required",
                message=f"Payment required. Minimum fee: {self.settings.cashu_min_fee_sats} sat(s).",
            )
            await self.relay_pool.broadcast_event(fb)
            return

        # 2. Deserialize Cashu Token
        try:
            token = decode_token(job.cashu_token)
        except CashuVerificationError as e:
            logger.warning("Job %s rejected: Malformed Cashu token (%s)", job.event_id[:8], e)
            fb = create_job_feedback_event(
                worker_pubkey=self.settings.public_key_hex,
                worker_privkey_bytes=self.settings.private_key_bytes,
                request_event_id=job.event_id,
                customer_pubkey=job.requester_pubkey,
                status="error",
                message=f"Invalid Cashu token: {e}",
            )
            await self.relay_pool.broadcast_event(fb)
            return

        # Check sat value meets fee requirement
        if token.total_amount < self.settings.cashu_min_fee_sats:
            logger.warning(
                "Job %s rejected: Insufficient payment (%d sats < %d required)",
                job.event_id[:8],
                token.total_amount,
                self.settings.cashu_min_fee_sats,
            )
            fb = create_job_feedback_event(
                worker_pubkey=self.settings.public_key_hex,
                worker_privkey_bytes=self.settings.private_key_bytes,
                request_event_id=job.event_id,
                customer_pubkey=job.requester_pubkey,
                status="payment-required",
                message=f"Insufficient fee: provided {token.total_amount} sats, required {self.settings.cashu_min_fee_sats} sats.",
            )
            await self.relay_pool.broadcast_event(fb)
            return

        # 3. Broadcast Feedback: Processing & Payment Verified
        fb_proc = create_job_feedback_event(
            worker_pubkey=self.settings.public_key_hex,
            worker_privkey_bytes=self.settings.private_key_bytes,
            request_event_id=job.event_id,
            customer_pubkey=job.requester_pubkey,
            status="processing",
            message=f"Payment of {token.total_amount} sats received. Verifying settlement...",
        )
        await self.relay_pool.broadcast_event(fb_proc)

        # 4. Atomic Ecash Settlement via Mint Swap (NUT-03)
        settled_sats = token.total_amount
        if self.settings.cashu_auto_swap:
            try:
                target_mint = token.primary_mint or self.settings.cashu_mint_url
                new_proofs, settled_sats = await self.mint_client.swap_proofs(
                    token.all_proofs, mint_url=target_mint
                )
                self.vault.add_settled_proofs(new_proofs)
                logger.info(
                    "Job %s ecash settled successfully (+%d sats | Vault Balance: %d sats)",
                    job.event_id[:8],
                    settled_sats,
                    self.vault.balance,
                )
            except CashuDoubleSpendError as e:
                logger.error("Job %s failed: Cashu double-spend detected (%s)", job.event_id[:8], e)
                fb_err = create_job_feedback_event(
                    worker_pubkey=self.settings.public_key_hex,
                    worker_privkey_bytes=self.settings.private_key_bytes,
                    request_event_id=job.event_id,
                    customer_pubkey=job.requester_pubkey,
                    status="error",
                    message="Ecash token already spent (double-spend rejected).",
                )
                await self.relay_pool.broadcast_event(fb_err)
                return
            except Exception as e:
                logger.error("Job %s failed: Mint settlement error: %s", job.event_id[:8], e)
                fb_err = create_job_feedback_event(
                    worker_pubkey=self.settings.public_key_hex,
                    worker_privkey_bytes=self.settings.private_key_bytes,
                    request_event_id=job.event_id,
                    customer_pubkey=job.requester_pubkey,
                    status="error",
                    message=f"Cashu mint swap failed: {e}",
                )
                await self.relay_pool.broadcast_event(fb_err)
                return

        # 5. Dispatch to AI Inference Engine
        logger.info("Dispatching prompt for Job %s to AI engine...", job.event_id[:8])
        try:
            ai_response = await self.ai_engine.generate(
                prompt=job.prompt,
                model=job.model,
            )
        except AIInferenceError as e:
            logger.error("Job %s AI inference failed: %s", job.event_id[:8], e)
            fb_err = create_job_feedback_event(
                worker_pubkey=self.settings.public_key_hex,
                worker_privkey_bytes=self.settings.private_key_bytes,
                request_event_id=job.event_id,
                customer_pubkey=job.requester_pubkey,
                status="error",
                message=f"AI inference failed: {e}",
            )
            await self.relay_pool.broadcast_event(fb_err)
            return

        # 6. Encrypt with NIP-44 v2 and Broadcast Kind 6000 Result
        result_event = create_job_result_event(
            worker_pubkey=self.settings.public_key_hex,
            worker_privkey_bytes=self.settings.private_key_bytes,
            request_event_id=job.event_id,
            customer_pubkey=job.requester_pubkey,
            prompt=job.prompt,
            result_text=ai_response,
            settled_sats=settled_sats,
            encrypt_response=True,
        )
        await self.relay_pool.broadcast_event(result_event)

        # 7. Broadcast Final Success Feedback
        fb_success = create_job_feedback_event(
            worker_pubkey=self.settings.public_key_hex,
            worker_privkey_bytes=self.settings.private_key_bytes,
            request_event_id=job.event_id,
            customer_pubkey=job.requester_pubkey,
            status="success",
            message="Job executed successfully. Result encrypted via NIP-44 v2.",
        )
        await self.relay_pool.broadcast_event(fb_success)
        logger.info("Job %s finalized and published to Nostr.", job.event_id[:8])

    async def run(self) -> None:
        """Main daemon lifecycle runner."""
        npub_str = pubkey_to_npub(self.settings.public_key_hex)
        logger.info("==================================================================")
        logger.info("PrivaVend Autonomous AI Data Vending Machine (DVM) Starting...")
        logger.info("Worker Pubkey (hex):  %s", self.settings.public_key_hex)
        logger.info("Worker Identity npub: %s", npub_str)
        logger.info("Relays:               %s", self.settings.relay_list)
        logger.info("Cashu Mint:           %s", self.settings.cashu_mint_url)
        logger.info("Min Fee:              %d sat(s)", self.settings.cashu_min_fee_sats)
        logger.info("AI Backend:           %s (Model: %s)", self.settings.ai_backend, self.settings.ai_model)
        logger.info("Target Filtering:     %s", "Targeted Only" if self.settings.require_targeted_pubkey else "Open Feed")
        logger.info("==================================================================")

        # Start relay subscription loops
        await self.relay_pool.start()

        # Wait until shutdown signal
        try:
            await self._shutdown_event.wait()
        finally:
            await self.shutdown()

    async def shutdown(self) -> None:
        """Gracefully terminates relays and pending tasks."""
        logger.info("PrivaVend daemon shutting down...")
        await self.relay_pool.stop()
        if self._active_tasks:
            logger.info("Awaiting %d pending job tasks...", len(self._active_tasks))
            await asyncio.gather(*self._active_tasks, return_exceptions=True)
        logger.info("Final Vault Statistics:")
        logger.info("- Total Sats Earned:   %d sats", self.vault.total_earned)
        logger.info("- Current Vault Sats:  %d sats", self.vault.balance)
        logger.info("PrivaVend daemon halted cleanly.")

    def trigger_shutdown(self) -> None:
        """Sets shutdown event trigger."""
        self._shutdown_event.set()


def main() -> None:
    """CLI entrypoint."""
    settings = get_settings()
    daemon = PrivaVendDaemon(settings)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def _sig_handler():
        logger.info("Shutdown signal received.")
        daemon.trigger_shutdown()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _sig_handler)
        except (NotImplementedError, AttributeError):
            # Windows compatibility for signal handlers
            pass

    try:
        loop.run_until_complete(daemon.run())
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received.")
        loop.run_until_complete(daemon.shutdown())
    finally:
        loop.close()


if __name__ == "__main__":
    main()
