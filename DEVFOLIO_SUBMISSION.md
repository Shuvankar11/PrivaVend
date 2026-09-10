# 🏆 PrivaVend - Devfolio Hackathon Submission Guide
**Event:** Bitshala BOSS Battle Hackathon  
**Project:** PrivaVend (Autonomous AI Data Vending Machine with Cashu & Nostr)

Use the contents below to fill out your Devfolio submission form (`devfolio.co/projects/privavend-26df/update`).

---

## 1. Project Info

### Project Name
```
PrivaVend
```

### Tagline (One-liner)
```
Zero-trace autonomous AI Data Vending Machine (DVM) settled off-chain via Cashu Chaumian Ecash over Nostr NIP-90.
```

---

## 2. Media Uploads

- **Project Logo (Square Icon):**  
  File located at: `D:\BOSS BATTLE\PrivaVend\assets\privavend_logo.png`
- **Project Media / Banner (16:9 Cover):**  
  File located at: `D:\BOSS BATTLE\PrivaVend\assets\privavend_banner.png`

---

## 3. The problem it solves (Copy & Paste below into Devfolio)

```markdown
### 🛑 The Problem: The AI Surveillance & Identity Trap
Modern AI inference is plagued by centralized surveillance and financial de-anonymization:
1. **Payment Identity Linkage:** Traditional AI APIs (OpenAI, Anthropic, AWS) require credit cards, KYC-linked bank accounts, or static Lightning invoices that permanently tie user identity, IP address, and financial records to the sensitive prompts submitted.
2. **Relay & Node Snoopability:** Sending AI requests across open networks exposes prompt payloads and query metadata to relay operators and intermediary nodes.
3. **Double-Spend & Settlement Vulnerability:** Traditional micro-metering models suffer from chargebacks or unpaid inference latency.

---

### ⚡ The Solution: PrivaVend
**PrivaVend** is a zero-trace, fully autonomous AI Data Vending Machine (DVM) implementing **Nostr NIP-90** and settled off-chain via **Cashu Chaumian Ecash (NUT-00 through NUT-07)** with end-to-end **NIP-44 (Version 2)** authenticated encryption.

Neither the AI worker, nor the Nostr relays, nor the Cashu mint can correlate who is paying with what is being asked.

#### 🔑 What Makes PrivaVend Revolutionary:
- **Zero-Trace Cashu Settlement (NUT-00 to NUT-07):**
  Clients embed blind-signed Cashu Ecash tokens (`cashuA...`) directly inside Nostr Kind 5000 job requests. PrivaVend connects to an open Cashu Mint and performs an **atomic swap (`POST /v1/swap`) BEFORE dispatching the prompt** to the AI inference loop. Once swapped, the worker holds settled ecash and the client cannot claw it back or double-spend it.
- **True End-to-End Encryption (NIP-44 v2):**
  PrivaVend encrypts the generated response using authenticated ChaCha20 encryption with power-of-two padding and HMAC-SHA256 authenticated tags, keyed directly to the requester's Secp256k1 public key. Relays and network observers see only ciphertext.
- **Decentralized NIP-90 Job Pipeline:**
  Operates autonomously on public Nostr relays without proprietary web servers. Emits real-time Kind 7000 feedback (`processing`, `payment-required`, `success`) and Kind 6000 job results.
- **Local & Modular AI Inference:**
  Runs completely private, sovereign local models via Ollama (`llama3`, `mistral`, `deepseek-r1`) with zero external API calls, plus resilient fallbacks for cloud failover.
```

---

## 4. Challenges I ran into (Copy & Paste below into Devfolio)

```markdown
1. **Cashu BDHKE Math & hash_to_curve in Pure Python:**
   Implementing NUT-00 cryptographic primitives required deriving Secp256k1 curve points from arbitrary secrets using the exact Cashu domain separator (`Secp256k1_HashToCurve_Cashu_`) and Euler's criterion for modular square roots. We solved this with verified curve point arithmetic and libsecp256k1 bindings.

2. **Strict Nostr NIP-44 (Version 2) Specification Alignment:**
   NIP-44 v2 requires a specific 76-byte HKDF expansion (32-byte encryption key, 12-byte ChaCha nonce, 32-byte auth key) combined with RFC 8439 12-byte nonce layout and power-of-two padding. We engineered a bit-for-bit compliant ChaCha20-HMAC engine verified against reference test vectors.

3. **Atomic Settlement Race Conditions:**
   Handling asynchronous Nostr events across multiple relays risked race conditions and duplicate inference executions. We implemented an atomic token swap against the mint before initiating inference, paired with LRU event deduplication and an async bounded semaphore.
```

---

## 5. Technologies Used (Copy & Paste or select in Devfolio tags)

- **Python 3.11+ / Asyncio**
- **Nostr Protocol (NIP-01, NIP-90, NIP-44 v2, BIP-173)**
- **Cashu Chaumian Ecash (NUT-00, NUT-01, NUT-02, NUT-03, NUT-07)**
- **Secp256k1 / BIP-340 Schnorr Signatures**
- **ChaCha20 & HMAC-SHA256 Authenticated Encryption**
- **Ollama / LLaMA3 / Mistral (Local AI Core)**
- **WebSockets / HTTPX / Pydantic**
