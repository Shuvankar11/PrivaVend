<p align="center">
  <img src="assets/privavend_logo.png" alt="PrivaVend Brand Logo" width="160" style="border-radius: 24px;" />
</p>

# ⚡ PrivaVend: Zero-Trace Autonomous AI Data Vending Machine (DVM)

> **Bitshala BOSS Battle Hackathon Submission**  
> *Bridging Cypherpunk Privacy, Nostr NIP-90, and Cashu Chaumian Ecash.*

---

## 🔑 Key Features & Cypherpunk Guarantees

1. **Chaumian Ecash Settlement (NUT-00 to NUT-07)**:
   - Accept blinded tokens (`cashuA...`).
   - Atomic swap (`POST /v1/swap`) executed **prior to inference** to prevent double-spends.
   - Proof state verification (`POST /v1/checkstate`).
   - In-memory vault tracks cumulative earnings without centralized databases.

2. **Nostr NIP-90 DVM Standard**:
   - **Kind 5000**: Ingests job requests with prompt payloads, cashu tokens, and optional model params.
   - **Kind 7000**: Real-time feedback (`processing`, `payment-required`, `error`, `success`).
   - **Kind 6000**: Verifiable job result publication.

3. **End-to-End NIP-44 (Version 2) Encryption**:
   - The AI output is encrypted with the requester's public key using ChaCha20, power-of-two padding, and HMAC-SHA256 authentication.
   - Only the private key holder who submitted the job can decrypt the inference result.

4. **Modular AI Engine**:
   - Primary: Local, private **Ollama** runner (`llama3`, `mistral`, `deepseek-r1`).
   - Fallback: External OpenAI-compatible APIs (Together AI, Groq, OpenRouter).
   - Offline Simulation: Intelligent fallback engine for local testing and zero-dependency CI.
   - Prompt sanitization and jailbreak boundary protection.

5. **Resilient Relay Pool**:
   - Simultaneous connections across multiple public Nostr relays (`relay.damus.io`, `nos.lol`, `relay.primal.net`).
   - Automatic reconnect with exponential backoff and background ping/pong heartbeats.
   - LRU deduplication across relays.

---

## 💻 Local Setup & Quickstart Guide

### 1. Installation

Requires Python 3.11+.

```bash
# Clone and enter the repository
git clone https://github.com/Shuvankar11/PrivaVend.git
cd PrivaVend

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

Copy the example environment configuration:

```bash
cp .env.example .env
```

Key configuration parameters inside `.env`:

| Variable | Description | Default |
|---|---|---|
| `NOSTR_PRIVATE_KEY` | Hex or `nsec1...` private key. Leave empty for auto-generated ephemeral key. | *Ephemeral* |
| `NOSTR_RELAYS` | Comma-separated WebSocket Nostr relays. | `wss://relay.damus.io,wss://nos.lol` |
| `CASHU_MINT_URL` | Cashu mint endpoint for verification & swap. | `https://mint.minibits.cash/Bitcoin` |
| `CASHU_MIN_FEE_SATS` | Minimum required satoshis per job request. | `1` |
| `CASHU_AUTO_SWAP` | Redeem incoming ecash proofs via `/v1/swap`. | `true` |
| `AI_BACKEND` | Engine: `ollama`, `openai_compatible`, or `mock`. | `ollama` |
| `AI_MODEL` | Default model identifier. | `llama3` |
| `OLLAMA_BASE_URL` | Ollama local endpoint. | `http://127.0.0.1:11434` |

---

### 3. Launch the PrivaVend Daemon

Run the autonomous worker daemon:

```bash
python -m worker.main
```

Startup output example:
```
[INFO] PrivaVend Autonomous AI Data Vending Machine (DVM) Starting...
[INFO] Worker Pubkey (hex):  c04ca59d9ea4fbac8ae1386727ed984805cf34547568f0a9db92e781513958fb
[INFO] Worker Identity npub: npub1cf5h4zew8kf7ymzf03n5hgjlkw9ntkfr4q402rlgh3wmavsjnfgsn9anmu
[INFO] Relays:               ['wss://relay.damus.io', 'wss://nos.lol']
[INFO] Cashu Mint:           https://mint.minibits.cash/Bitcoin
[INFO] Min Fee:              1 sat(s)
[INFO] AI Backend:           ollama (Model: llama3)
[INFO] Relay pool started across 2 relays.
```

---

### 4. Run the Test Client

In a separate terminal, use `scripts/test_client.py` to dispatch a simulated job with an ecash token:

```bash
# Send a code audit job with an auto-generated 5-sat mock Cashu token:
python scripts/test_client.py --prompt "Conduct a security audit of a 2-of-3 Bitcoin multisig taproot script."

# Or target a specific PrivaVend worker by its npub or hex pubkey:
python scripts/test_client.py --worker-pubkey <WORKER_NPUB> --prompt "Explain Chaumian Ecash in 3 bullet points."
```

The test client will:
1. Generate an ephemeral client Nostr keypair.
2. Formulate a valid NUT-00 `cashuA...` token.
3. Sign and broadcast a Kind 5000 event to the relay.
4. Listen for Kind 7000 feedback (`processing`).
5. Receive the Kind 6000 result event.
6. Decrypt the response via NIP-44 v2 and display the output.

---

### 5. Running the Test Suite

Execute the full pytest suite:

```bash
python -m pytest -v
```

Output:
```
tests/test_cashu.py::test_hash_to_curve PASSED
tests/test_cashu.py::test_negate_point PASSED
tests/test_cashu.py::test_split_amount PASSED
tests/test_cashu.py::test_token_encode_decode PASSED
tests/test_cashu.py::test_invalid_token PASSED
tests/test_cashu.py::test_mint_swap_and_vault PASSED
tests/test_cashu.py::test_checkstate PASSED
tests/test_e2e.py::test_end_to_end_job_processing PASSED
tests/test_nostr.py::test_bech32_roundtrip PASSED
tests/test_nostr.py::test_schnorr_signatures PASSED
tests/test_nostr.py::test_nostr_event_lifecycle PASSED
tests/test_nostr.py::test_nip44_v2_encryption PASSED
tests/test_nostr.py::test_nip90_job_parsing PASSED
tests/test_nostr.py::test_nip90_feedback_and_result_generation PASSED

============================= 14 passed in 1.30s ==============================
```

---

## 🧭 Mission & Overview

**PrivaVend** is a decentralized, zero-trace, autonomous AI Data Vending Machine (DVM) built for the Nostr protocol. Settled off-chain with untraceable **Cashu Chaumian Ecash** tokens, PrivaVend ensures that neither the AI inference provider nor the Nostr relay operators can correlate a user's prompt or identity with their payment history.

```
       +--------------------------------------------------------------+
       |                        CLIENT / USER                         |
       +--------------------------------------------------------------+
           |                                                      ^
           | 1. Kind 5000 Job Request                             | 6. Kind 6000 Result
           |    - Prompt: "Audit smart contract"                  |    - NIP-44 v2 Encrypted
           |    - Ecash: "cashuA..." (NUT-00)                     |    - Decrypted locally
           v                                                      |
    +---------------+                                     +---------------+
    |  Nostr Relay  | ==================================> |  Nostr Relay  |
    |  (e.g. nos.lol)                                     | (e.g. damus.io)
    +---------------+                                     +---------------+
           |                                                      ^
           | 2. Inbound Kind 5000 Feed                            | 5. Kind 6000 Broadcast
           v                                                      |
+-----------------------------------------------------------------------------+
|                              PRIVAVEND DAEMON                               |
|                                                                             |
|  [1. Inbound Event Parser]                                                  |
|      - Extracts prompt, cashu token, model, and requester pubkey            |
|                                                                             |
|  [2. Atomic Cashu Settlement (NUT-03)]                                      |
|      - Connects to Cashu Mint (e.g., https://mint.minibits.cash/Bitcoin)   |
|      - Swaps client inputs for fresh daemon outputs (prevents double-spend) |
|                                                                             |
|  [3. NIP-90 Feedback (Kind 7000)]                                           |
|      - Broadcasts "processing" status feedback to customer                  |
|                                                                             |
|  [4. AI Inference Engine]                                                   |
|      - Sanitizes inputs and guards prompt boundaries                        |
|      - Dispatches to local Ollama (llama3/mistral) or external API          |
|                                                                             |
|  [5. NIP-44 v2 Encryption & Output Packaging]                               |
|      - Computes ECDH shared secret (HKDF-Extract + Expand)                  |
|      - Encrypts result with ChaCha20 + HMAC-SHA256 authenticated tag         |
|      - Signs BIP-340 Schnorr signature and publishes Kind 6000 result       |
+-----------------------------------------------------------------------------+
```

---

## 📂 Repository Layout

```
PrivaVend/
├── worker/
│   ├── __init__.py           # Package version and metadata
│   ├── config.py             # Pydantic settings & keypair management
│   ├── main.py               # Main daemon runner and graceful lifecycle
│   └── core/
│       ├── __init__.py
│       ├── nostr.py          # NIP-01, NIP-44 v2, NIP-90, Bech32, and Relay Pool
│       ├── cashu.py          # NUT-00 to NUT-07 ecash engine & atomic mint swap
│       └── ai_engine.py      # Modular LLM runner (Ollama / API / Mock)
├── scripts/
│   └── test_client.py        # Interactive CLI to send jobs + cashu tokens
├── tests/
│   ├── test_cashu.py         # Cashu BDHKE, tokens, and swap unit tests
│   ├── test_nostr.py         # BIP-340, NIP-44 v2, NIP-01, and NIP-90 unit tests
│   └── test_e2e.py           # End-to-end daemon & client integration test
├── .env.example              # Template environment variables
├── requirements.txt          # Production dependencies
└── README.md                 # Complete documentation
```

---

## 📜 Protocol Standards Implemented

| Standard | Description | Implementation Status |
|---|---|---|
| **NIP-01** | Basic Nostr protocol, canonical serialization, event signing | ✅ Implemented |
| **NIP-44** | Encrypted direct message payloads (v2 ChaCha20 + HMAC) | ✅ Implemented |
| **NIP-90** | Data Vending Machine: Kind 5000 (Request), 7000 (Feedback), 6000 (Result) | ✅ Implemented |
| **BIP-173** | Bech32 encoding/decoding (`npub`, `nsec`) | ✅ Implemented |
| **BIP-340** | Schnorr signatures over Secp256k1 | ✅ Implemented (Native libsecp256k1) |
| **NUT-00** | Cashu Ecash token format, BDHKE cryptography, `hash_to_curve` | ✅ Implemented |
| **NUT-01** | Mint public keysets | ✅ Implemented |
| **NUT-02** | Keysets discovery | ✅ Implemented |
| **NUT-03** | Atomic swap / settlement | ✅ Implemented |
| **NUT-07** | Proof state verification (`/v1/checkstate`) | ✅ Implemented |

---

## ⚖️ License

MIT License - Open Source Cypherpunk Software. Built for the Bitshala BOSS Battle Hackathon.
