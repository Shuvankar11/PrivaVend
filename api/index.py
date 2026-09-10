"""
Vercel Serverless Function for PrivaVend Web Playground
Provides live REST endpoints for protocol status and end-to-end NIP-90 + Cashu simulations.
"""

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler
import secrets

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    import coincurve
    from worker.core.cashu import Proof, encode_token_v3, decode_token, CashuMintClient
    from worker.core.nostr import (
        NostrEvent, compute_conversation_key, nip44_encrypt, nip44_decrypt,
        pubkey_to_npub, create_job_feedback_event, create_job_result_event
    )
    from worker.core.ai_engine import AIEngine
except Exception as e:
    coincurve = None
    import_error = str(e)


class handler(BaseHTTPRequestHandler):
    def _send_json(self, status_code: int, data: dict):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/api/info", "/api"):
            self._send_json(200, {
                "name": "PrivaVend Autonomous AI DVM",
                "status": "online",
                "protocols": {
                    "nostr": ["NIP-01", "NIP-90 (DVM)", "NIP-44 v2 (Encrypted DM)"],
                    "cashu": ["NUT-00", "NUT-01", "NUT-02", "NUT-03 (Swap)", "NUT-07 (Checkstate)"]
                },
                "default_relays": ["wss://relay.damus.io", "wss://nos.lol"],
                "default_mint": "https://mint.minibits.cash/Bitcoin",
                "version": "0.1.0"
            })
        elif path == "/api/token":
            # Generate a test mock token
            proofs = [
                {"id": "demo_keyset", "amount": 1, "secret": secrets.token_hex(16), "C": "02" + secrets.token_hex(32)},
                {"id": "demo_keyset", "amount": 4, "secret": secrets.token_hex(16), "C": "02" + secrets.token_hex(32)}
            ]
            import base64
            payload = {"token": [{"mint": "https://mint.minibits.cash/Bitcoin", "proofs": proofs}], "memo": "PrivaVend Demo Token"}
            b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
            token_str = f"cashuA{b64}"
            self._send_json(200, {
                "token": token_str,
                "amount_sats": 5,
                "memo": "PrivaVend Demo Token"
            })
        else:
            self._send_json(404, {"error": "Endpoint not found"})

    def do_POST(self):
        path = self.path.split("?")[0]
        if path in ("/api/simulate", "/api/job"):
            try:
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length).decode("utf-8")
                req_data = json.loads(body) if body else {}

                prompt = req_data.get("prompt", "Perform a security audit of an atomic escrow contract with 2-of-3 multisig.")
                cashu_token = req_data.get("cashu_token") or req_data.get("ecash_token", "")
                model = req_data.get("model", "llama3")

                # Ephemeral worker identity
                worker_sk = secrets.token_bytes(32)
                worker_pk = coincurve.PrivateKey(worker_sk).public_key.format(compressed=True)[1:].hex()

                # Client identity
                client_sk = secrets.token_bytes(32)
                client_pk = coincurve.PrivateKey(client_sk).public_key.format(compressed=True)[1:].hex()

                start_time = time.time()

                # Token validation
                if not cashu_token:
                    # Auto-generate demo token if empty
                    proofs = [Proof(id="demo_keyset", amount=5, secret=secrets.token_hex(16), C="02" + secrets.token_hex(32))]
                    cashu_token = encode_token_v3("https://mint.minibits.cash/Bitcoin", proofs, memo="Auto Demo Token")

                token = decode_token(cashu_token)
                total_sats = token.total_amount

                # Kind 5000 Request Event
                req_event = NostrEvent(
                    pubkey=client_pk,
                    created_at=int(time.time()),
                    kind=5000,
                    tags=[["i", prompt, "text"], ["cashu", cashu_token], ["param", "model", model]],
                    content=prompt
                )
                req_event.sign(client_sk)

                # Feedback Kind 7000 Event
                fb_event = create_job_feedback_event(
                    worker_pubkey=worker_pk,
                    worker_privkey_bytes=worker_sk,
                    request_event_id=req_event.id,
                    customer_pubkey=client_pk,
                    status="processing",
                    message=f"Cashu ecash of {total_sats} sats settled via atomic swap. Dispatching to AI engine..."
                )

                # AI Inference
                engine = AIEngine(backend="mock", default_model=model)
                import asyncio
                ai_text = asyncio.run(engine.generate(prompt, model=model))

                # Encrypted Kind 6000 Result Event
                res_event = create_job_result_event(
                    worker_pubkey=worker_pk,
                    worker_privkey_bytes=worker_sk,
                    request_event_id=req_event.id,
                    customer_pubkey=client_pk,
                    prompt=prompt,
                    result_text=ai_text,
                    settled_sats=total_sats,
                    encrypt_response=True
                )

                # Client Decryption test
                conv_key = compute_conversation_key(client_sk, bytes.fromhex(worker_pk))
                decrypted_result = nip44_decrypt(conv_key, res_event.content)

                elapsed_ms = int((time.time() - start_time) * 1000)

                self._send_json(200, {
                    "success": True,
                    "elapsed_ms": elapsed_ms,
                    "result": decrypted_result,
                    "encrypted_ciphertext": res_event.content,
                    "settlement": {
                        "settled_sats": total_sats,
                        "mint": token.primary_mint or "https://mint.minibits.cash/Bitcoin",
                        "proofs_count": len(token.all_proofs),
                        "status": "ATOMICALLY_SWAPPED"
                    },
                    "job_request": {
                        "kind": 5000,
                        "id": req_event.id,
                        "requester_pubkey": client_pk,
                        "prompt": prompt,
                        "model": model
                    },
                    "feedback": {
                        "kind": 7000,
                        "status": "processing",
                        "id": fb_event.id
                    }
                })
            except Exception as e:
                self._send_json(500, {"success": False, "error": str(e)})
        else:
            self._send_json(404, {"error": "Endpoint not found"})
