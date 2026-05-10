import time
from nlp_filter import should_block
from test_dataset import TEST_CASES

def run_benchmark():
    print(f"{'='*60}")
    print(f"📊 QUANTUM GUARD GATEWAY: ACCURACY BENCHMARK")
    print(f"{'='*60}\n")
    
    passed = 0
    total = len(TEST_CASES)
    
    print(f"{'PROMPT':<50} | {'EXPECTED':<10} | {'ACTUAL':<10} | {'RESULT'}")
    print("-" * 85)

    for case in TEST_CASES:
        start_time = time.time()
        
        # Run your logic
        _, analysis = should_block(case["text"])
        actual_tier = analysis["tier"]
        
        latency = (time.time() - start_time) * 1000 # in ms
        
        is_correct = actual_tier == case["expected"]
        if is_correct:
            passed += 1
            result_icon = "✅"
        else:
            result_icon = "❌"

        # Truncate text for display
        display_text = (case["text"][:47] + '..') if len(case["text"]) > 47 else case["text"]
        
        print(f"{display_text:<50} | {case['expected']:<10} | {actual_tier:<10} | {result_icon} ({latency:.0f}ms)")

    accuracy = (passed / total) * 100
    print(f"\n{'='*60}")
    print(f"📈 FINAL ACCURACY: {accuracy:.2f}% ({passed}/{total} correct)")
    print(f"{'='*60}")

if __name__ == "__main__":
    run_benchmark()