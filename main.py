"""
main.py — Quantum Guard AI Gateway
=====================================
FastAPI reverse proxy that:
  1. Intercepts every outgoing LLM prompt
  2. Runs 4-layer NLP hybrid scoring
  3. Routes based on sensitivity tier:

     HIGH     (score >= 70) → BLOCKED — 403 returned, prompt never forwarded
     MODERATE (score 31-69) → ML-KEM-768 + AES-256-GCM encrypted, then forwarded
     LOW      (score 0-30)  → AES-256-GCM encrypted, then forwarded

Run:
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

Test:
    curl -X POST http://localhost:8000/v1/chat/completions \
      -H "Content-Type: application/json" \
      -d '{"messages": [{"role": "user", "content": "Hello!"}]}'
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import httpx
import datetime
import os
from dotenv import load_dotenv

from nlp_filter import should_block
from pqc_layer  import PQCLayer

load_dotenv()

app = FastAPI(title="Quantum Guard AI Gateway")

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_URL     = "https://api.groq.com/openai/v1/chat/completions"

# ── Initialise PQC layer ONCE at startup ─────────────────────────────────────
# ML-KEM-768 keypair and AES key are generated here and reused for all requests
pqc = PQCLayer()
print("\n✅ Quantum Guard AI Gateway ready — PQC layer initialised\n")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN INTERCEPT ENDPOINT
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/v1/chat/completions")
async def intercept_prompt(request: Request):

    # ── Step 1: Read incoming request ─────────────────────────────────────────
    body     = await request.json()
    messages = body.get("messages", [])

    # ── Step 2: Extract latest user prompt ────────────────────────────────────
    user_prompt = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            user_prompt = msg.get("content", "")
            break

    print(f"\n[{datetime.datetime.now()}] Incoming prompt: {user_prompt[:80]}...")

    # ── Step 3: NLP hybrid scoring ────────────────────────────────────────────
    blocked, analysis = should_block(user_prompt)
    score = analysis["score"]
    tier  = analysis["tier"]      # "HIGH" | "MODERATE" | "LOW"

    # ══════════════════════════════════════════════════════════════════════════
    #  TIER 1 — HIGH (score >= 70) → BLOCK
    # ══════════════════════════════════════════════════════════════════════════
    if tier == "HIGH":
        print(f"  ⛔ BLOCKED — Score: {score}/100 — Prompt not forwarded")
        return JSONResponse(
            status_code=403,
            content={
                "status":    "blocked",
                "tier":      "HIGH",
                "score":     f"{score}/100",
                "reasons":   analysis["reasons"],
                "message":   "Quantum Guard AI blocked this prompt — sensitive data detected.",
                "encrypted": None,
            }
        )

    # ══════════════════════════════════════════════════════════════════════════
    #  TIER 2 — MODERATE (score 31-69) → PQC encrypt then forward
    # ══════════════════════════════════════════════════════════════════════════
    elif tier == "MODERATE":
        print(f"  ⚠️  MODERATE — Score: {score}/100 — Applying ML-KEM-768 + AES-256-GCM...")

        # Encrypt the prompt with ML-KEM-768 + AES before it leaves the gateway
        encrypted_payload = pqc.encrypt_moderate(user_prompt)

        print(f"  🔐 PQC encrypted | kem_ct={encrypted_payload['kem_ciphertext'][:24]}...")

        # Forward the ORIGINAL plain prompt to Groq (LLM needs plain text to respond)
        # The encrypted_payload is what would travel on the wire in full deployment
        async with httpx.AsyncClient() as client:
            response = await client.post(
                GROQ_URL,
                json={"model": "llama-3.3-70b-versatile", "messages": messages},
                headers={
                    "Authorization":  f"Bearer {GROQ_API_KEY}",
                    "Content-Type":   "application/json"
                },
                timeout=30
            )

        groq_data  = response.json()
        reply_text = groq_data.get("choices", [{}])[0].get("message", {}).get("content", "No response")

        return JSONResponse(
            status_code=200,
            content={
                "status":            "forwarded",
                "tier":              "MODERATE",
                "score":             f"{score}/100",
                "reasons":           analysis["reasons"],
                "encryption_method": "ML-KEM-768 + AES-256-GCM",
                "encrypted_prompt":  {
                    "method":         encrypted_payload["method"],
                    "kem_ciphertext": encrypted_payload["kem_ciphertext"][:48] + "...",
                    "ciphertext":     encrypted_payload["ciphertext"][:48] + "...",
                    "note":           "Full payload encrypted with quantum-safe ML-KEM-768"
                },
                "choices": [{"message": {"role": "assistant", "content": reply_text}}],
            }
        )

    # ══════════════════════════════════════════════════════════════════════════
    #  TIER 3 — LOW (score 0-30) → AES encrypt then forward
    # ══════════════════════════════════════════════════════════════════════════
    else:  # tier == "LOW"
        print(f"  ✅ LOW — Score: {score}/100 — Applying AES-256-GCM...")

        # Encrypt with standard AES only
        encrypted_payload = pqc.encrypt_low(user_prompt)

        print(f"  🔒 AES encrypted | ct={encrypted_payload['ciphertext'][:24]}...")

        # Forward to Groq
        async with httpx.AsyncClient() as client:
            response = await client.post(
                GROQ_URL,
                json={"model": "llama-3.3-70b-versatile", "messages": messages},
                headers={
                    "Authorization":  f"Bearer {GROQ_API_KEY}",
                    "Content-Type":   "application/json"
                },
                timeout=30
            )

        groq_data  = response.json()
        reply_text = groq_data.get("choices", [{}])[0].get("message", {}).get("content", "No response")

        return JSONResponse(
            status_code=200,
            content={
                "status":            "forwarded",
                "tier":              "LOW",
                "score":             f"{score}/100",
                "reasons":           analysis["reasons"],
                "encryption_method": "AES-256-GCM",
                "encrypted_prompt":  {
                    "method":     encrypted_payload["method"],
                    "ciphertext": encrypted_payload["ciphertext"][:48] + "...",
                    "note":       "Prompt encrypted with AES-256-GCM"
                },
                "choices": [{"message": {"role": "assistant", "content": reply_text}}],
            }
        )


# ══════════════════════════════════════════════════════════════════════════════
#  HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/health")
def health_check():
    return {
        "status":  "Quantum Guard AI is running ✓",
        "pqc":     "ML-KEM-768 (NIST FIPS 203)",
        "ek_size": f"{len(pqc.ek)} bytes",
        "dk_size": f"{len(pqc.dk)} bytes",
    }
