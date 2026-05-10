🚀 Execution Guide (Step-by-Step)
To run the full system, you must open three separate terminals in the project root directory.

Terminal 1: Ollama (The Brain)
Start the local Small Language Model (SLM). We are using Llama 3.2:3b for better reasoning.

Bash
ollama run llama3.2:3b
Note: Keep this running. It serves the API at localhost:11434.

Terminal 2: FastAPI Gateway (The Police)
Start the Uvicorn server to host the security logic and PQC engine.

Bash
# Activate env first
venv\Scripts\activate

# Start the server
uvicorn main:app --reload --port 8000
Note: The server will load spaCy (en_core_web_lg) and BART models on startup.

Terminal 3: Testing & Benchmarking
Use this terminal to verify the system performance or send custom prompts.

Option A: Run the Accuracy Benchmark
This runs the 45-prompt test suite to calculate the current accuracy.

Bash
venv\Scripts\activate
python benchmark.py
Option B: Manual Test (CURL)
Test a specific "High Risk" leak manually to see the block in action:

Bash
curl -X POST "http://localhost:8000/v1/chat/completions" ^
-H "Content-Type: application/json" ^
-d "{\"messages\": [{\"role\": \"user\", \"content\": \"My bank PIN is 1234\"}]}"
