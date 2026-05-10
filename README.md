# Quantum Guard: AI-Powered Security Gateway
**Unisys Innovation Program (UIP) Year 17 - Phase 1**  
**Institution:** R V College of Engineering (RVCE), Bangalore  
**Team:** Innovative Project Team (GDG/ACM/Coding Club)

## 🚀 Project Overview
Quantum Guard is a next-generation security gateway designed to intercept and analyze NLP prompts before they reach Large Language Models (LLMs). It integrates **Post-Quantum Cryptography (ML-KEM-768)** to ensure future-proof data encryption and a **BART-based Small Language Model (SLM)** for real-time malicious intent scoring and Explainable AI (XAI) feedback.

---

## 🛠️ Prerequisites
*   **Python 3.9+**
*   **Git** (properly configured with `.gitignore`)
*   **Groq API Key** (for LLM processing)

---

## 📥 Local Setup

### 1. Repository Setup
```cmd
git clone <your-repository-link>
cd Backend_Cl
2. Environment Configuration
Terminal 1:
Create and activate your virtual environment to isolate dependencies:

DOS
python -m venv venv
venv\Scripts\activate
3. Install Dependencies
DOS
pip install -r requirements.txt
4. API Credentials
Create a .env file in the root directory (this file is ignored by Git for security):

Plaintext
GROQ_API_KEY=your_api_key_here
🚦 How to Run (2-Terminal Workflow)
Terminal 1: The Gateway Server (FastAPI)
Run the server with auto-reload enabled. This is ideal for the development phase as it refreshes the server every time you modify main.py, nlp_filter.py, or pqc_layer.py.

DOS
venv\Scripts\activate
uvicorn main:app --reload --port 8000
Wait for the message: Uvicorn running on http://127.0.0.1:8000

Terminal 2: Testing & Client Requests
Keep Terminal 1 running and open a new Command Prompt to simulate a client request:

DOS
curl -X POST "[http://127.0.0.1:8000/process](http://127.0.0.1:8000/process)" ^
     -H "Content-Type: application/json" ^
     -d "{\"prompt\": \"Analyze the following encrypted PQC packet\"}"
📂 Project Structure
main.py – FastAPI entry point and gateway logic.

nlp_filter.py – SLM scoring engine and XAI reasoning.

pqc_layer.py – ML-KEM-768 encryption/decryption module.

requirements.txt – Project dependencies (FastAPI, Uvicorn, Torch, etc.).

.gitignore – Ensures venv/ and .env are not tracked by Git.


