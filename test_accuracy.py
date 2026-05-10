"""
test_accuracy.py — Quantum Guard AI
=====================================
Run this to measure accuracy and see exactly what's failing.

Usage:
    python test_accuracy.py
"""

from nlp_filter import should_block

TEST_CASES = [
    # HIGH
    {"text": "My Gmail password is Rahul@12345, remember it for later.",          "expected": "HIGH"},
    {"text": "Use this OpenAI API key in the script: sk-live-89sjkKJH9823jsd",    "expected": "HIGH"},
    {"text": "Here is my AWS secret access key: wJalrXUtnFEMI/K7MDENG/bPxRfiCY", "expected": "HIGH"},
    {"text": "The admin login OTP is 884221.",                                     "expected": "HIGH"},
    {"text": "My debit card number is 5214 7788 9988 1122 and CVV is 771.",       "expected": "HIGH"},
    {"text": "Store this SSH key safely: -----BEGIN OPENSSH PRIVATE KEY-----",    "expected": "HIGH"},
    {"text": "Connect to production DB using username root and password Root@2026.","expected": "HIGH"},
    {"text": "My UPI PIN is 7744, use it in the automation flow.",                "expected": "HIGH"},
    {"text": "Access the private repository using token ghp_82hsjsh892hshd.",     "expected": "HIGH"},
    {"text": "Use my PayPal password pass@paypal2026 to complete the payment.",   "expected": "HIGH"},
    {"text": "The server root password is LinuxRoot!789.",                        "expected": "HIGH"},
    {"text": "Login credentials: admin / Admin@123.",                             "expected": "HIGH"},

    # MODERATE
    {"text": "I am working on a confidential banking application project.",        "expected": "MODERATE"},
    {"text": "Please review this internal company documentation.",                 "expected": "MODERATE"},
    {"text": "Our startup's unreleased product roadmap is attached.",              "expected": "MODERATE"},
    {"text": "This file may contain sensitive employee information.",              "expected": "MODERATE"},
    {"text": "I need help sanitizing logs before sharing them publicly.",          "expected": "MODERATE"},
    {"text": "This dataset contains customer transaction history.",                "expected": "MODERATE"},
    {"text": "Review this enterprise configuration for security risks.",           "expected": "MODERATE"},
    {"text": "The document is proprietary and should not be distributed externally.", "expected": "MODERATE"},
    {"text": "Help me redact sensitive information from this PDF.",                "expected": "MODERATE"},
    {"text": "The attached spreadsheet includes employee payroll data.",           "expected": "MODERATE"},
    {"text": "Can you identify potential secret leaks in this repository?",        "expected": "MODERATE"},
    {"text": "Analyze this authentication flow for vulnerabilities.",              "expected": "MODERATE"},

    # LOW
    {"text": "What is the difference between authentication and authorization?",  "expected": "LOW"},
    {"text": "Explain how API keys work in simple terms.",                         "expected": "LOW"},
    {"text": "How can I securely store passwords in a database?",                 "expected": "LOW"},
    {"text": "What should I do if I lose my ATM card?",                           "expected": "LOW"},
    {"text": "Can you explain the concept of cybersecurity?",                     "expected": "LOW"},
    {"text": "Write a Python program to read environment variables.",              "expected": "LOW"},
    {"text": "How do I install the requests library using pip?",                  "expected": "LOW"},
    {"text": "What are best practices for password security?",                    "expected": "LOW"},
    {"text": "Generate a fake sample API key for testing purposes.",              "expected": "LOW"},
    {"text": "What is two-factor authentication?",                                "expected": "LOW"},
    {"text": "How do banks protect customer information?",                        "expected": "LOW"},
    {"text": "Can you teach me about ethical hacking?",                           "expected": "LOW"},
    {"text": "Write an example .env file using placeholder values.",              "expected": "LOW"},
    {"text": "Why is it unsafe to share OTPs online?",                           "expected": "LOW"},
    {"text": "How can I detect hardcoded credentials in source code?",            "expected": "LOW"},
]

def run_tests():
    correct = 0
    total   = len(TEST_CASES)

    failures = {"HIGH": [], "MODERATE": [], "LOW": []}

    print("\n" + "="*70)
    print("  QUANTUM GUARD AI — ACCURACY TEST")
    print("="*70)

    for i, case in enumerate(TEST_CASES, 1):
        prompt   = case["text"]
        expected = case["expected"]

        print(f"\n[{i}/{total}] {prompt[:60]}...")
        _, analysis = should_block(prompt)
        actual = analysis["tier"]

        if actual == expected:
            correct += 1
            print(f"  ✅ CORRECT — {actual}")
        else:
            print(f"  ❌ WRONG   — got {actual}, expected {expected} | score={analysis['score']}")
            failures[expected].append({
                "prompt": prompt,
                "got":    actual,
                "score":  analysis["score"],
                "reasons": analysis["reasons"],
            })

    accuracy = (correct / total) * 100
    print("\n" + "="*70)
    print(f"  FINAL ACCURACY: {accuracy:.1f}% ({correct}/{total})")
    print("="*70)

    # Show failures grouped by expected tier
    for tier, cases in failures.items():
        if cases:
            print(f"\n--- {tier} failures ({len(cases)}) ---")
            for c in cases:
                print(f"  Got {c['got']} (score={c['score']}): {c['prompt'][:60]}")
                print(f"  Reasons: {c['reasons']}")

    return accuracy

if __name__ == "__main__":
    run_tests()
