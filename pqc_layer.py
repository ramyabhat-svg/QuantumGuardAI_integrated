"""
pqc_layer.py — Quantum Guard AI
=================================
Handles encryption for MODERATE and LOW scored prompts.

Called by main.py like this:
    from pqc_layer import PQCLayer
    pqc = PQCLayer()                          # init once at startup
    payload = pqc.encrypt_moderate(prompt)    # ML-KEM-768 + AES
    payload = pqc.encrypt_low(prompt)         # AES only

Install:
    pip install kyber-py cryptography
"""

import os
import json
import logging
from kyber_py.ml_kem import ML_KEM_768
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger("pqc_layer")


class PQCLayer:
    """
    Manages one ML-KEM-768 keypair and one AES key for the gateway lifetime.
    Instantiate ONCE in main.py at startup.
    """

    def __init__(self):
        # ML-KEM-768 keypair for MODERATE prompts
        self.ek, self.dk = ML_KEM_768.keygen()
        log.info(f"[PQC] ML-KEM-768 keypair ready | ek={len(self.ek)}B dk={len(self.dk)}B")

        # AES key for LOW prompts
        self.aes_key = os.urandom(32)
        log.info(f"[PQC] AES-256 key ready | {len(self.aes_key)}B")

    # ── MODERATE: ML-KEM-768 + AES-256-GCM ───────────────────────────────────

    def encrypt_moderate(self, prompt: str) -> dict:
        """
        Quantum-safe encryption for MODERATE scored prompts.
        Uses ML-KEM-768 key encapsulation + AES-256-GCM.
        Returns a dict that travels over the network.
        """
        # Step 1: ML-KEM encapsulation — derive shared secret
        shared_secret, kem_ct = ML_KEM_768.encaps(self.ek)

        # Step 2: AES-256-GCM encrypt the prompt using shared secret
        nonce  = os.urandom(12)
        aes_ct = AESGCM(shared_secret[:32]).encrypt(nonce, prompt.encode(), None)

        payload = {
            "method":         "ML-KEM-768 + AES-256-GCM",
            "kem_ciphertext": kem_ct.hex(),
            "nonce":          nonce.hex(),
            "ciphertext":     aes_ct.hex(),
        }
        log.info(f"[PQC] MODERATE encrypted | kem_ct={len(kem_ct)}B aes_ct={len(aes_ct)}B")
        return payload

    def decrypt_moderate(self, payload: dict) -> str:
        """Decrypt a MODERATE payload. Used at the receiving gateway end."""
        kem_ct        = bytes.fromhex(payload["kem_ciphertext"])
        shared_secret = ML_KEM_768.decaps(self.dk, kem_ct)
        nonce         = bytes.fromhex(payload["nonce"])
        aes_ct        = bytes.fromhex(payload["ciphertext"])
        return AESGCM(shared_secret[:32]).decrypt(nonce, aes_ct, None).decode()

    # ── LOW: AES-256-GCM only ─────────────────────────────────────────────────

    def encrypt_low(self, prompt: str) -> dict:
        """
        Standard AES-256-GCM encryption for LOW scored prompts.
        No PQC needed — prompt is not sensitive enough to warrant it.
        """
        nonce  = os.urandom(12)
        aes_ct = AESGCM(self.aes_key).encrypt(nonce, prompt.encode(), None)

        payload = {
            "method":     "AES-256-GCM",
            "nonce":      nonce.hex(),
            "ciphertext": aes_ct.hex(),
        }
        log.info(f"[PQC] LOW encrypted | aes_ct={len(aes_ct)}B")
        return payload

    def decrypt_low(self, payload: dict) -> str:
        """Decrypt a LOW payload."""
        nonce  = bytes.fromhex(payload["nonce"])
        aes_ct = bytes.fromhex(payload["ciphertext"])
        return AESGCM(self.aes_key).decrypt(nonce, aes_ct, None).decode()
