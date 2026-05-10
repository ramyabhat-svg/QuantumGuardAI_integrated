# interceptor.py
# Run with: mitmproxy -s interceptor.py --listen-port 8080

from mitmproxy import http
import json
import requests

GATEWAY_URL = "http://localhost:8000/v1/chat/completions"

class QuantumGuardInterceptor:

    def request(self, flow: http.HTTPFlow):
        """Intercepts every outgoing HTTP request from the browser."""

        # Only intercept LLM API calls
        target_hosts = [
            "api.openai.com",
            "chat.openai.com", 
            "gemini.google.com",
            "api.anthropic.com",
            "api.groq.com",
        ]

        if not any(host in flow.request.pretty_host for host in target_hosts):
            return  # let non-LLM traffic pass through normally

        if flow.request.method != "POST":
            return

        print(f"\n[INTERCEPTED] {flow.request.pretty_host}{flow.request.path}")

        try:
            # Read the original request body
            body = json.loads(flow.request.content)
            
            # Forward to your Quantum Guard gateway
            response = requests.post(
                GATEWAY_URL,
                json=body,
                timeout=60
            )
            
            gateway_response = response.json()
            status = gateway_response.get("status", "unknown")
            tier   = gateway_response.get("tier", "unknown")
            score  = gateway_response.get("score", "?")

            print(f"[GATEWAY]    Status={status} | Tier={tier} | Score={score}")

            if status == "blocked":
                # Replace the response with a block message
                flow.response = http.Response.make(
                    403,
                    json.dumps({
                        "error": {
                            "message": f"🛡️ Quantum Guard AI blocked this prompt. Score: {score}. Reason: {gateway_response.get('reasons', [])}",
                            "type": "quantum_guard_block",
                            "tier": tier,
                        }
                    }),
                    {"Content-Type": "application/json"}
                )
                print(f"[BLOCKED]    Prompt not forwarded to LLM")

            else:
                # Let the request go through but log the encryption
                enc = gateway_response.get("encrypted_prompt", {})
                method = enc.get("method", "unknown")
                print(f"[ENCRYPTED]  Method: {method}")
                # Request continues to real LLM normally

        except Exception as e:
            print(f"[ERROR] Gateway error: {e} — letting request pass")


addons = [QuantumGuardInterceptor()]