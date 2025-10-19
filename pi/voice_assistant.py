import numpy as np
import sounddevice as sd
import pvorca
import pvporcupine
import pvcheetah
import requests
import os
import time
import threading
import subprocess # REQUIRED: For running network commands
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# -----------------------------
# CONFIGURATION
# -----------------------------
ACCESS_KEY = os.getenv("ACCESS_KEY")
KEYWORD_PATH = "Wake-up-Tim_en_raspberry-pi_v3_0_0.ppn"
FLASK_API_URL = "http://localhost:5001/chat"
STT_SILENCE_TIMEOUT = 2.0

# --- DEVICE SELECTION ---
MIC_DEVICE_INDEX = 0
SPEAKER_DEVICE_INDEX = 1

# --- Global variable to signal wake word detection ---
wake_word_detected = threading.Event()

# -----------------------------
# FILE PATH VALIDATION
# -----------------------------
if not os.path.exists(KEYWORD_PATH):
    print(f"Error: Porcupine keyword file not found at '{KEYWORD_PATH}'")
    exit()

# -----------------------------
# INITIALIZE MODELS
# -----------------------------
print("🔈 Initializing Picovoice Models...")
try:
    orca = pvorca.create(access_key=ACCESS_KEY, model_path='orca_params_en_male.pv')
    cheetah = pvcheetah.create(access_key=ACCESS_KEY, endpoint_duration_sec=1.0)
    porcupine = pvporcupine.create(access_key=ACCESS_KEY, keyword_paths=[KEYWORD_PATH], sensitivities=[0.8])
except Exception as e:
    print(f"Error initializing Picovoice models: {e}")
    exit()

# -----------------------------
# HELPER FUNCTIONS
# -----------------------------

def get_network_diagnostics():
    """Runs network commands and returns a formatted report string."""
    print("📋 Generating network diagnostics snapshot...")
    report = "--- Live Network Diagnostics Report ---\n"
    try:
        ping_output = subprocess.check_output(
            ['ping', '-c', '1', '8.8.8.8'],
            stderr=subprocess.STDOUT,
            universal_newlines=True)
        report += "Internet Ping (to 8.8.8.8): SUCCESS\n"
    except subprocess.CalledProcessError:
        report += "Internet Ping (to 8.8.8.8): FAILED\n"
    try:
        iwconfig_output = subprocess.check_output(
            ['iwconfig', 'wlan0'],
            stderr=subprocess.STDOUT,
            universal_newlines=True)
        signal_line = [line for line in iwconfig_output.split('\n') if 'Signal level' in line]
        if signal_line:
            report += f"Wi-Fi Status: {signal_line[0].strip()}\n"
    except (subprocess.CalledProcessError, FileNotFoundError):
        report += "Wi-Fi Status: Could not retrieve Wi-Fi information.\n"
    try:
        ip_output = subprocess.check_output(['hostname', '-I'], universal_newlines=True).strip()
        report += f"Local IP Address: {ip_output}\n"
    except subprocess.CalledProcessError:
        report += "Local IP Address: NOT FOUND\n"
    report += "---------------------------------------\n"
    return report

def speak(text: str):
    """Converts text to speech and plays it back with resampling if needed."""
    print(f"Assistant: {text}")
    try:
        pcm_samples, _ = orca.synthesize(text)
        orca_sr = orca.sample_rate
        target_sr = 48000  # BT67 native sample rate
        
        # Resample if necessary
        if orca_sr != target_sr:
            num_resampled = int(len(pcm_samples) * target_sr / orca_sr)
            resampled_time = np.linspace(0, len(pcm_samples) - 1, num_resampled)
            original_time = np.arange(len(pcm_samples))
            resampled_audio = np.interp(resampled_time, original_time, pcm_samples)
            pcm_samples = resampled_audio.astype(np.int16)
            playback_sr = target_sr
        else:
            playback_sr = orca_sr
        
        sd.play(np.array(pcm_samples, dtype=np.int16), samplerate=playback_sr, device=SPEAKER_DEVICE_INDEX)
        sd.wait()
    except Exception as e:
        print(f"Error in text-to-speech function: {e}")

def transcribe_realtime():
    """Uses a robust resampling pipeline to capture audio for Cheetah STT."""
    print("👂 Listening...")
    transcript = ""
    stream = None
    try:
        TARGET_SAMPLE_RATE = cheetah.sample_rate
        mic_info = sd.query_devices(MIC_DEVICE_INDEX, 'input')
        NATIVE_SAMPLE_RATE = int(mic_info['default_samplerate'])
        resampling_needed = NATIVE_SAMPLE_RATE != TARGET_SAMPLE_RATE
        last_spoken_time = time.time()

        def stt_callback(indata, frames, time_info, status):
            nonlocal transcript, last_spoken_time
            if status: print(status)
            if resampling_needed:
                num_resampled = int(len(indata) * TARGET_SAMPLE_RATE / NATIVE_SAMPLE_RATE)
                resampled_time = np.linspace(0, len(indata) - 1, num_resampled)
                original_time = np.arange(len(indata))
                resampled_audio = np.interp(resampled_time, original_time, indata.flatten())
                pcm = (resampled_audio * 32767).astype(np.int16)
            else:
                pcm = (indata * 32767).astype(np.int16)
            num_frames = len(pcm) // cheetah.frame_length
            for i in range(num_frames):
                frame = pcm[i * cheetah.frame_length:(i + 1) * cheetah.frame_length]
                partial_transcript, _ = cheetah.process(frame)
                if partial_transcript:
                    print(f"  ... {partial_transcript}", end="", flush=True)
                    transcript += partial_transcript
                    last_spoken_time = time.time()
        stream = sd.InputStream(
            device=MIC_DEVICE_INDEX, samplerate=NATIVE_SAMPLE_RATE, channels=1,
            dtype='float32', blocksize=2048, callback=stt_callback)
        stream.start()
        while time.time() - last_spoken_time < STT_SILENCE_TIMEOUT:
            time.sleep(0.1)
        final_transcript = cheetah.flush()
        transcript += final_transcript
        print()
    except Exception as e:
        print(f"Error during transcription: {e}")
    finally:
        if stream:
            stream.stop()
            stream.close()
    return transcript.strip()

def get_ai_response(prompt: str):
    """Generates diagnostics, combines them with a structured prompt, and sends to our custom AI model."""
    print("🧠 Thinking...")
    try:
        diagnostics_report = get_network_diagnostics()
        
        # Using the structured format that the new Modelfile expects
        full_prompt = (
            f"[DIAGNOSTICS]\n{diagnostics_report}\n\n"
            f"[USER_QUESTION]\n{prompt}"
        )
        
        # Using the new custom model and no longer sending a system prompt
        payload = {
            "model": "network-assistant",
            "prompt": full_prompt,
            "stream": False
        }
        response = requests.post(FLASK_API_URL, json=payload, timeout=300)
        response.raise_for_status()
        return response.json().get('response', "Sorry, I received an empty response.")
    except requests.exceptions.RequestException as e:
        print(f"API Error: {e}")
        return "I'm having trouble connecting to my brain right now."

def listen_for_wake_word():
    """Main wake word detection loop using the fixed resampling method."""
    stream = None
    try:
        TARGET_SAMPLE_RATE = porcupine.sample_rate
        mic_info = sd.query_devices(MIC_DEVICE_INDEX, 'input')
        NATIVE_SAMPLE_RATE = int(mic_info['default_samplerate'])
        resampling_needed = NATIVE_SAMPLE_RATE != TARGET_SAMPLE_RATE

        def porcupine_callback(indata, frames, time_info, status):
            if wake_word_detected.is_set(): return
            if status: print(status)
            if resampling_needed:
                num_resampled = int(len(indata) * TARGET_SAMPLE_RATE / NATIVE_SAMPLE_RATE)
                resampled_time = np.linspace(0, len(indata) - 1, num_resampled)
                original_time = np.arange(len(indata))
                resampled_audio = np.interp(resampled_time, original_time, indata.flatten())
                pcm = (resampled_audio * 32767).astype(np.int16)
            else:
                pcm = (indata * 32767).astype(np.int16)
            num_frames = len(pcm) // porcupine.frame_length
            for i in range(num_frames):
                frame = pcm[i * porcupine.frame_length:(i + 1) * porcupine.frame_length]
                result = porcupine.process(frame)
                if result >= 0:
                    wake_word_detected.set()
        stream = sd.InputStream(
            device=MIC_DEVICE_INDEX, samplerate=NATIVE_SAMPLE_RATE, channels=1,
            dtype='float32', blocksize=2048, callback=porcupine_callback)
        stream.start()
        print(f"\nWaiting for wake word ('Wake Up Tim')... Press Ctrl+C to exit.\n")
        while not wake_word_detected.is_set():
            time.sleep(0.1)
    finally:
        if stream:
            stream.stop()
            stream.close()

# -----------------------------
# MAIN APPLICATION LOGIC
# -----------------------------
def main():
    try:
        while True:
            wake_word_detected.clear()
            listen_for_wake_word()
            print("🚀 Wake word detected!")
            speak("Yes?")
            user_text = transcribe_realtime()
            if user_text:
                print(f"You said: {user_text}")
                if user_text.lower() in ["goodbye", "exit", "stop"]:
                    speak("Shutting down. Goodbye!")
                    break
                else:
                    response = get_ai_response(user_text)
                    speak(response)
            else:
                speak("Sorry, I didn't catch that. Please try again.")
    except KeyboardInterrupt:
        print("\nExiting gracefully...")
    finally:
        print("Cleaning up resources.")
        if 'porcupine' in locals(): porcupine.delete()
        if 'cheetah' in locals(): cheetah.delete()
        if 'orca' in locals(): orca.delete()

if __name__ == "__main__":
    main()

