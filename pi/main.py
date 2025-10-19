from flask import Flask, request
import requests

# This is the Flask server that will receive requests from your voice_assistant.py
# and forward them to the Ollama AI model.

app = Flask(__name__)

# The URL for your local Ollama instance
OLLAMA_API_URL = "http://localhost:11435/api/generate"

@app.route('/chat', methods=['POST'])
def chat():
    """
    Receives a request from the voice assistant, passes the entire payload
    to Ollama, and returns the model's response.
    """
    try:
        # Get the entire JSON payload sent from voice_assistant.py
        incoming_payload = request.json
        print(f"Received payload: {incoming_payload}") # For debugging

        # --- This is the key logic ---
        # We forward the exact payload to Ollama. This ensures that the
        # correct model ('network-assistant') and the full, structured
        # prompt are used by the AI.
        response = requests.post(
            OLLAMA_API_URL,
            json=incoming_payload,
            timeout=300
        )
        
        response.raise_for_status()
        response_data = response.json()
        
        # Return the AI's response back to the voice assistant
        if 'response' in response_data:
            return {'response': response_data['response'].strip()}
        else:
            return {'response': 'Error: Unexpected response from the model.'}, 500

    except requests.exceptions.RequestException as e:
        print(f"Error connecting to Ollama: {e}")
        return {'response': 'Error: Could not connect to the local AI model.'}, 503
    except Exception as e:
        print(f"An unexpected server error occurred: {e}")
        return {'response': 'An unexpected server error occurred.'}, 500

if __name__ == '__main__':
    # This server will run on port 5001, which is what your
    # voice_assistant.py is configured to talk to.
    app.run(host='0.0.0.0', port=5001)


