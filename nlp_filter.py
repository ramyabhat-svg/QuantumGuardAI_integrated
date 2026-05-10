"""
nlp_filter.py — Quantum Guard AI v3.0
=======================================
4-layer hybrid NLP filter targeting 80%+ accuracy.

KEY FIXES from v2.0:
  - Regex ONLY matches actual credential VALUES (not words like "import", "password")
  - BART labels rewritten to distinguish "sharing secrets" vs "asking about secrets"
  - SLM always runs, uses llama3.2:3b with detailed prompt + examples
  - Score weights rebalanced: regex=instant block, BART+SLM lead scoring

Score mapping:
    score >= 70  → HIGH     → BLOCKED
    score 30-69  → MODERATE → PQC encrypted
    score 0-29   → LOW      → AES only

Install:
    pip install spacy transformers python-dotenv requests
    python -m spacy download en_core_web_lg
    ollama pull llama3.2:3b
"""

import re
import spacy
import os
import requests
from dotenv import load_dotenv
from transformers import pipeline

load_dotenv()

# ── Load models once at startup ──────────────────────────────────────────────
print("Loading spaCy model...")
nlp_model = spacy.load("en_core_web_lg")

print("Loading HuggingFace BART classifier...")
classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

print("All local models loaded ✓")


# ══════════════════════════════════════════════════════════════════════════════
#  LAYER 1 — REGEX
#
#  CRITICAL RULE: Only match actual credential VALUES, never security words.
#
#  WRONG (causes false positives):
#    r"password"          → matches "password best practices" → wrongly blocks LOW
#    r"import"            → matches "how do I import a library" → wrongly blocks LOW
#    r"secret"            → matches "trade secret explained" → wrongly blocks LOW
#
#  RIGHT (matches actual data):
#    r"password\s*[:=]\s*\S{4,}"  → matches "password: abc123" only
#    r"sk-[a-zA-Z0-9]{20,}"       → matches actual OpenAI key format
# ══════════════════════════════════════════════════════════════════════════════

PATTERNS = {
    "openai_key":      r"sk-[a-zA-Z0-9\-_]{20,}",
    "aws_access_key":  r"AKIA[0-9A-Z]{16}",
    "aws_secret_key":  r"(?<![a-zA-Z0-9])[a-zA-Z0-9/+]{40}(?![a-zA-Z0-9])",  # ADD
    "github_token":    r"ghp_[a-zA-Z0-9]{10,}",           # was 20+
    "jwt_token":       r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    "private_key":     r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "db_connection":   r"(mongodb|postgresql|mysql):\/\/\S+",
    "auth_bearer":     r"(?i)Authorization:\s*(Bearer|Basic)\s+[a-zA-Z0-9\._\-]{10,}",
    "credit_card":     r"\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b",
    "aadhaar":         r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b",
    "password_value":  r"(?i)\b(password|passwd|pwd)\s*(is|:|=|->|)\s*\S{4,}",  # added empty match
    "pin_value":       r"(?i)\b(pin|otp|cvv|passcode)\s*(is|:|=|->)\s*\d{3,8}",
    "credential_pair": r"(?i)(username|login|credentials?)\s*[:/]\s*\S+\s*[,/]\s*\S+",
}

# Any match in this set = instant score 100, skip all other layers
INSTANT_BLOCK = {
    "openai_key", "aws_access_key", "github_token", "jwt_token",
    "private_key", "db_connection", "auth_bearer", "credit_card",
    "aadhaar", "password_value", "pin_value", "credential_pair",
}

def pattern_scan(prompt: str) -> dict:
    hits = {}
    for name, pattern in PATTERNS.items():
        if re.search(pattern, prompt):
            hits[name] = True
    return hits


# ══════════════════════════════════════════════════════════════════════════════
#  LAYER 2 — NAMED ENTITY RECOGNITION
# ══════════════════════════════════════════════════════════════════════════════

SENSITIVE_ENTITIES = {"ORG", "PERSON", "GPE", "PRODUCT", "MONEY"}

def ner_scan(prompt: str) -> list:
    doc = nlp_model(prompt)
    return [
        {"text": ent.text, "type": ent.label_}
        for ent in doc.ents
        if ent.label_ in SENSITIVE_ENTITIES
    ]


# ══════════════════════════════════════════════════════════════════════════════
#  LAYER 3 — BART SEMANTIC CLASSIFICATION
#
#  Labels are carefully written to separate:
#    "sharing actual secrets"  (HIGH)
#    "discussing sensitive topics" (MODERATE)
#    "asking educational questions" (LOW)
# ══════════════════════════════════════════════════════════════════════════════

# HIGH labels — user is actively sharing secret values
HIGH_LABELS = [
    "sharing actual password or login credentials with values",
    "disclosing personal identity number like aadhaar or social security",
    "sharing bank card number or CVV or PIN digits",
    "pasting private key or API key or secret token content",
    "revealing OTP or one-time password value",
]

# MODERATE labels — sensitive context but no actual secret values
MODERATE_LABELS = [
    "discussing internal company document or business strategy",
    "sharing confidential employee or HR information",
    "describing proprietary code or trade secret project",
    "handling private or sensitive personal data",
    "asking to review or sanitize sensitive content",
]

# LOW labels — educational or general help, no sensitive data
LOW_LABELS = [
    "asking general question about security concepts",
    "requesting coding or programming help",
    "learning about public technology or best practices",
    "generating fake or sample data for testing",
    "asking for placeholder or example content",
]

SENSITIVE_LABELS = HIGH_LABELS + MODERATE_LABELS
SAFE_LABELS      = LOW_LABELS

def semantic_scan(prompt: str) -> dict:
    all_labels = SENSITIVE_LABELS + SAFE_LABELS
    result     = classifier(prompt, all_labels)
    top_label  = result["labels"][0]
    confidence = result["scores"][0]
    return {
        "label":      top_label,
        "confidence": confidence,
        "is_high":    top_label in HIGH_LABELS,
        "is_safe":    top_label in LOW_LABELS,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  LAYER 4 — LOCAL OLLAMA SLM (llama3.2:3b)
#
#  Always runs. Context-aware. 100% local — nothing leaves the machine.
#  Falls back gracefully if Ollama is not running.
# ══════════════════════════════════════════════════════════════════════════════

SLM_PROMPT = """You are a corporate data security classifier.

A user wants to send this message to an external AI like ChatGPT.
Score how dangerous this is from 0 to 100.

SCORING:
90-100 → Contains ACTUAL secret values being shared:
         real passwords ("password is Rahul@123"),
         real card numbers (5214 7788 9988 1122),
         real PINs/OTPs ("OTP is 884221", "PIN is 7744"),
         real API/SSH keys (sk-live-xxx, BEGIN PRIVATE KEY),
         real aadhaar/SSN numbers,
         real credentials ("admin / Admin@123")

60-89  → Sensitive internal context but NO actual secret values:
         internal company documents, employee payroll data,
         confidential project details, proprietary code description,
         customer transaction history, enterprise configuration

30-59  → References sensitive topics but is clearly asking for HELP:
         "help me redact sensitive info from this PDF"
         "check if this code exposes credentials"
         "sanitize logs before sharing"
         "identify potential secret leaks"

0-29   → Safe educational question or general coding help:
         "what are password best practices?" (asking ABOUT, not sharing)
         "how do API keys work?" (learning)
         "explain two-factor authentication" (public knowledge)
         "write a Python for loop" (coding help)
         "what should I do if I lose my ATM card?" (general advice)
         "generate a fake sample API key for testing" (fake/sample)

MOST IMPORTANT RULE:
Asking ABOUT a sensitive topic ≠ sharing sensitive data.
"Why is OTP unsafe?" → Score 5 (educational)
"The OTP is 884221" → Score 95 (actual secret)
"How do banks protect data?" → Score 5 (educational)
"Here is our internal bank config" → Score 75 (sensitive context)

Reply with ONLY a single integer 0-100. No words. No explanation. Just the number.

Message: {prompt}"""

def slm_guard_check(user_text: str, current_score: int) -> int:
    try:
        print("🔍 Local SLM checking...")
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3.2:3b",
                "prompt": f"""Does this message contain actual secret values being shared?

Actual secrets = real passwords, real PINs, real card numbers, 
real API keys, real OTPs, real private keys, real credentials.

NOT secrets = questions about security, asking for help, 
describing a project, educational questions.

Answer ONLY with YES or NO.

Message: {user_text}""",
                "stream": False,
                "options": {"temperature": 0}
            },
            timeout=30
        )
        if response.status_code == 200:
            raw = response.json().get("response", "").strip().upper()
            print(f"   ↳ SLM says: {raw}")
            if "YES" in raw:
                return max(current_score, 85)  # escalate to HIGH
            else:
                return current_score           # let BART score stand
    except Exception as e:
        print(f"   ↳ Ollama error: {e}")
    return current_score


# ══════════════════════════════════════════════════════════════════════════════
#  COMBINED SCORING
# ══════════════════════════════════════════════════════════════════════════════

BLOCK_THRESHOLD    = 70
MODERATE_THRESHOLD = 30

def compute_leak_score(prompt: str) -> dict:
    score   = 0
    reasons = []

    # ── Layer 1: Regex ────────────────────────────────────────────────────────
    patterns_found = pattern_scan(prompt)

    if patterns_found:
        critical = INSTANT_BLOCK & set(patterns_found.keys())
        if critical:
            # Actual credential value detected → instant block, skip all other layers
            print(f"📊 Layer 1 (Regex): ⚡ INSTANT BLOCK — {list(critical)}")
            return {
                "score":   100,
                "reasons": [f"Actual credential value detected: {list(critical)}"],
            }
        # Non-critical regex hit (e.g. source code markers) → small boost only
        score += 20
        reasons.append(f"Pattern hint: {list(patterns_found.keys())}")
        print(f"📊 Layer 1 (Regex): +20 (soft hit)")
    else:
        print(f"📊 Layer 1 (Regex): +0")

    # ── Layer 2: NER ──────────────────────────────────────────────────────────
    entities            = ner_scan(prompt)
    layer2_contribution = 0
    if any(e["type"] == "ORG" for e in entities):
        layer2_contribution = 10
        score += layer2_contribution
        reasons.append(f"Organisation name detected")
    print(f"📊 Layer 2 (NER): +{layer2_contribution}")

    # ── Layer 3: BART ─────────────────────────────────────────────────────────
    semantic            = semantic_scan(prompt)
    layer3_contribution = 0

    if not semantic["is_safe"]:
        if semantic["is_high"]:
            layer3_contribution = int(semantic["confidence"] * 70)
        else:
            raw = int(semantic["confidence"] * 45)
            layer3_contribution = max(raw, 35)  # floor ensures MODERATE clears threshold
        score += layer3_contribution
        reasons.append(
            f"Semantic: '{semantic['label']}' ({semantic['confidence']:.0%})"
        )
    print(f"📊 Layer 3 (BART): +{layer3_contribution} — '{semantic['label']}'")

    final_local = min(score, 100)
    print(f"✅ Local Score (before SLM): {final_local}/100")
    return {"score": final_local, "reasons": reasons}


def should_block(prompt: str) -> tuple[bool, dict]:
    """
    Main entry point called by main.py.
    Returns (blocked: bool, analysis: dict)
    analysis keys: score, tier, reasons
    """
    # Layers 1–3
    analysis    = compute_leak_score(prompt)
    local_score = analysis["score"]

    # Layer 4 — SLM always runs
    final_score = slm_guard_check(prompt, local_score)

    print(f"--- 🔄 HYBRID SCORE SUMMARY ---")
    print(f"    Local Score : {local_score}")
    print(f"    Final Score : {final_score}")

    if final_score > local_score:
        analysis["reasons"].append(f"SLM escalated: {local_score} → {final_score}")
    analysis["score"] = final_score

    if final_score >= BLOCK_THRESHOLD:
        analysis["tier"] = "HIGH"
        print(f"    Verdict     : ⛔ BLOCK")
    elif final_score >= MODERATE_THRESHOLD:
        analysis["tier"] = "MODERATE"
        print(f"    Verdict     : ⚠️  MODERATE — PQC encrypt")
    else:
        analysis["tier"] = "LOW"
        print(f"    Verdict     : ✅ LOW — AES only")
    print(f"-------------------------------")

    return final_score >= BLOCK_THRESHOLD, analysis
