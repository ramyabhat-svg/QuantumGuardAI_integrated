"""
nlp_filter.py — Quantum Guard AI
==================================
4-layer hybrid NLP filter.

Layer 1: Regex pattern matching
Layer 2: spaCy Named Entity Recognition
Layer 3: HuggingFace BART zero-shot semantic classification
Layer 4: Groq Llama SLM second opinion (only when score < 70)

Score mapping used by main.py:
    score >= 70  → HIGH   → BLOCKED
    score 31-69  → MODERATE → PQC encrypted (ML-KEM-768 + AES)
    score 0-30   → LOW    → AES only

Install:
    pip install spacy transformers groq python-dotenv
    python -m spacy download en_core_web_lg
"""

import re
import spacy
import os
from groq import Groq
from dotenv import load_dotenv
from transformers import pipeline

load_dotenv()

# ── Load models once when the file is imported ───────────────────────────────
print("Loading spaCy model...")
nlp = spacy.load("en_core_web_lg")

print("Loading HuggingFace classifier...")
classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

print("All models loaded ✓")


# ── LAYER 1: Pattern Matching ─────────────────────────────────────────────────

PATTERNS = {
    "openai_key":    r"sk-[a-zA-Z0-9-_]{10,}",
    "aws_key":       r"AKIA[0-9A-Z]{16}",
    "db_connection": r"(mongodb|postgresql|mysql):\/\/[^\s]+",
    "jwt_token":     r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    "private_key":   r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "ip_address":    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "source_code":   r"def |class |import |SELECT |DROP TABLE|<\?php",
    "internal_hint": r"internal|confidential|proprietary|secret|private",
}

def pattern_scan(prompt: str) -> dict:
    hits = {}
    for name, pattern in PATTERNS.items():
        if re.search(pattern, prompt):
            hits[name] = True
    return hits


# ── LAYER 2: Named Entity Recognition ────────────────────────────────────────

SENSITIVE_ENTITIES = {"ORG", "PERSON", "GPE", "PRODUCT", "MONEY"}

def ner_scan(prompt: str) -> list:
    doc = nlp(prompt)
    found = []
    for ent in doc.ents:
        if ent.label_ in SENSITIVE_ENTITIES:
            found.append({"text": ent.text, "type": ent.label_})
    return found


# ── LAYER 3: Semantic Classification ─────────────────────────────────────────

SENSITIVE_LABELS = [
    "proprietary source code",
    "internal business document",
    "confidential employee information",
    "trade secret or intellectual property",
    "internal financial data",
]
SAFE_LABELS = ["general knowledge question", "public information"]

def semantic_scan(prompt: str) -> dict:
    all_labels = SENSITIVE_LABELS + SAFE_LABELS
    result = classifier(prompt, all_labels)
    return {
        "label":      result["labels"][0],
        "confidence": result["scores"][0]
    }


# ── LAYER 4: SLM Refinement ───────────────────────────────────────────────────

def slm_guard_check(user_text, current_score):
    """Refines score using Llama-3 if local models are uncertain."""
    if current_score < 70:
        try:
            print(f"  🔍 SLM requesting second opinion...")
            response = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[
                    {"role": "system", "content": "You are a Security Guard. Analyze text for data leaks (passwords, secrets). Respond with ONLY a single integer from 0 to 100."},
                    {"role": "user",   "content": f"Analyze this: {user_text}"}
                ],
                temperature=0,
                max_tokens=5
            )
            slm_score = int(response.choices[0].message.content.strip())
            return max(current_score, slm_score)
        except Exception as e:
            print(f"SLM Check Failed: {e}")
            return current_score
    return current_score


# ── COMBINED LEAK SCORE ───────────────────────────────────────────────────────

BLOCK_THRESHOLD    = 95   # HIGH   → BLOCKED
MODERATE_THRESHOLD = 30   # MODERATE → PQC encrypted

def compute_leak_score(prompt: str) -> dict:
    score   = 0
    reasons = []

    # Layer 1 — Regex
    patterns_found        = pattern_scan(prompt)
    layer1_contribution   = 0
    if patterns_found:
        layer1_contribution = 60
        score += layer1_contribution
        reasons.append(f"Pattern detected: {list(patterns_found.keys())}")
    print(f"📊 Layer 1 (Regex) Contribution: +{layer1_contribution}")

    # Layer 2 — NER
    entities             = ner_scan(prompt)
    layer2_contribution  = 0
    if any(e["type"] == "ORG" for e in entities):
        layer2_contribution = 10
        score += layer2_contribution
        reasons.append("Organisation name detected")
    print(f"📊 Layer 2 (NER) Contribution: +{layer2_contribution} ({len(entities)} entities found)")

    # Layer 3 — Semantic (BART)
    semantic             = semantic_scan(prompt)
    layer3_contribution  = 0
    if semantic["label"] not in SAFE_LABELS:
        layer3_contribution = int(semantic["confidence"] * 30)
        score += layer3_contribution
        reasons.append(f"Semantic risk: {semantic['label']}")
    print(f"📊 Layer 3 (BART) Contribution: +{layer3_contribution} (Confidence: {semantic['confidence']:.2f})")

    final_local_score = min(score, 100)
    print(f"✅ Total Local Score (Before SLM): {final_local_score}/100")

    return {"score": final_local_score, "reasons": reasons}


def should_block(prompt: str) -> tuple[bool, dict]:
    """
    Returns (blocked: bool, analysis: dict)

    analysis contains:
        score    : 0–100
        tier     : "HIGH" | "MODERATE" | "LOW"
        reasons  : list of strings
    """
    # Step 1: Local layers
    analysis    = compute_leak_score(prompt)
    local_score = analysis["score"]

    # Step 2: SLM second opinion
    final_score = slm_guard_check(prompt, local_score)

    # Step 3: Log comparison
    print(f"--- 🔄 HYBRID SCORE SUMMARY ---")
    print(f"    Initial Local Score: {local_score}")
    print(f"    SLM Adjusted Score:  {final_score}")

    if final_score > local_score:
        analysis["reasons"].append(
            f"SLM Escalation: Upgraded from {local_score} → {final_score}"
        )

    analysis["score"] = final_score

    # Step 4: Assign tier
    if final_score >= BLOCK_THRESHOLD:
        analysis["tier"] = "HIGH"
        print(f"    Final Verdict:       ⛔ BLOCK (HIGH)")
    elif final_score >= MODERATE_THRESHOLD:
        analysis["tier"] = "MODERATE"
        print(f"    Final Verdict:       ⚠️  MODERATE — PQC encrypt")
    else:
        analysis["tier"] = "LOW"
        print(f"    Final Verdict:       ✅ LOW — AES only")
    print(f"-------------------------------")

    blocked = final_score >= BLOCK_THRESHOLD
    return blocked, analysis
