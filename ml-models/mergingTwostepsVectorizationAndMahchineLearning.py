# The Final Block: The Complete, Interactive IPS Application Layer

import pandas as pd
import re
import tensorflow as tf
import pickle
from tensorflow.keras.preprocessing.sequence import pad_sequences
import numpy as np

print("--- Initializing The Full IPS Engine ---")

# ==============================================================================
#  GLOBAL CONFIGURATION & ASSET LOADING
# ==============================================================================

# --- File Paths (Dynamic) ---
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VECTORIZER_DATA_PATH = os.path.join(BASE_DIR, 'phase1_feature_dataset1111111111 (2).xlsx')
ML_TOKENIZER_PATH = os.path.join(BASE_DIR, 'tokenizer.pickle')
ML_MODEL_PATH = os.path.join(BASE_DIR, 'ips_model.keras')
MAX_SEQUENCE_LENGTH = 100 # This must match the ML model's training parameter

# --- Load All Assets ---
try:
    # Load the ML model and its tokenizer
    print("Loading ML model and tokenizer...")
    with open(ML_TOKENIZER_PATH, 'rb') as handle:
        ml_tokenizer = pickle.load(handle)
    ml_model = tf.keras.models.load_model(ML_MODEL_PATH)
    print("✔️ ML assets loaded successfully.")
    
    # Load the Vectorizer's knowledge base
    print("Loading Vectorizer knowledge base...")
    vectorizer_knowledge_base = pd.read_excel(VECTORIZER_DATA_PATH, sheet_name='Sheet1')
    print("✔️ Vectorizer assets loaded successfully.")
    
    assets_loaded = True
except Exception as e:
    print(f"❌ FATAL ERROR loading assets: {e}")
    print("Please ensure all required files are uploaded: vectorizer excel, tokenizer.pickle, and ips_model.keras")
    assets_loaded = False
    
# ==============================================================================
#  ENGINE DEFINITIONS (Vectorizer & Hybrid ML Pipeline)
# ==============================================================================

# Your CommandVectorizer remains the same powerful engine as before
class CommandVectorizer:
    def __init__(self, df):
        self.knowledge_base = pd.Series(df.flag.values, index=df.Command.astype(str)).to_dict()
        self.known_command_stems = sorted(self.knowledge_base.keys(), key=len, reverse=True)

    def _get_token_flag(self, token, is_first):
        if is_first:
            if token in self.knowledge_base: return self.knowledge_base[token]
            for stem in self.known_command_stems:
                if token.startswith(stem): return self.knowledge_base[stem]
        if token in ['|', '&&', ';', '||', '>']: return 12
        if token.startswith(('-', '--')) and len(token) > 1: return 10
        if token.startswith(('http://', 'https://', 'ftp://')): return 7
        if '/' in token and len(token) > 1: return 11
        if '.' in token and token not in ['.', '..']: return 6
        if token.isdigit(): return 15
        return 8

    def vectorize(self, command_chain):
        tokens = command_chain.strip().split()
        vector, is_next_cmd = [], True
        for token in tokens:
            vector.append(self._get_token_flag(token, is_next_cmd))
            is_next_cmd = True if token in ['|', '&&', ';', '||'] else False
        return vector

# Your HybridPredictionPipeline also remains the same
class HybridPredictionPipeline:
    TRIPWIRE_RULES = {'wget ': 0.8, 'curl ': 0.8, 'nc ': 0.8, '/etc/shadow': 1.0, 'mimikatz': 1.0}
    def __init__(self, model, tokenizer, max_len):
        self.model = model
        self.tokenizer = tokenizer
        self.max_len = max_len
        self.user_histories = {}

    def _run_tripwire_scan(self, command):
        for keyword, risk in self.TRIPWIRE_RULES.items():
            if re.search(keyword, command, re.IGNORECASE): return risk
        return 0.0

    def predict(self, user_id, command):
        heuristic_risk = self._run_tripwire_scan(command)
        if user_id not in self.user_histories: self.user_histories[user_id] = []
        self.user_histories[user_id].append(command)
        
        text = " ; ".join(self.user_histories[user_id])
        seq = self.tokenizer.texts_to_sequences([text])
        padded = pad_sequences(seq, maxlen=self.max_len, padding='pre', truncating='pre')
        contextual_risk = self.model.predict(padded, verbose=0)[0][0]
        
        final_risk = max(heuristic_risk, contextual_risk)
        reason = "Heuristic Match" if heuristic_risk > contextual_risk else "Contextual Pattern"
        
        if final_risk > 0.5:
            return f"🔴 MALICIOUS (Confidence: {final_risk:.2%}, Reason: {reason})"
        else:
            return f"🟢 BENIGN (Confidence: {1-final_risk:.2%})"

# ==============================================================================
#  THE REAL-TIME APPLICATION LAYER
# ==============================================================================
class InteractiveIPSSession:
    def __init__(self, vectorizer_engine, ml_engine):
        self.vectorizer = vectorizer_engine
        self.ml_predictor = ml_engine
        self.current_user = "default_user"

    def start(self):
        print("\n--- [ Full AI-Powered IPS Terminal ] ---")
        print("Enter a command to see its vector and ML prediction.")
        print("Meta-Commands: 'exit', 'quit', 'switch_user'")
        
        user_input = input(f"Enter User ID to track (or press Enter for '{self.current_user}'): ").strip()
        if user_input: self.current_user = user_input
        
        while True:
            try:
                prompt = f"[{self.current_user}] ~$ "
                command = input(prompt).strip()

                if command.lower() in ["exit", "quit"]: break
                if command.lower() == "switch_user":
                    new_user = input("Enter new User ID: ").strip()
                    if new_user: self.current_user = new_user; print(f"Switched to user: '{self.current_user}'")
                    continue
                if not command: continue
                
                # --- The Core AI Flow ---
                # 1. Get the Heuristic Vector
                output_vector = self.vectorizer.vectorize(command)
                
                # 2. Get the Deep Learning Prediction
                ml_result = self.ml_predictor.predict(self.current_user, command)
                
                # 3. Display Both Results
                print(f"  -> Heuristic Vector: {output_vector}")
                print(f"  -> ML Prediction   : {ml_result}")

            except KeyboardInterrupt: print("\nSession terminated."); break
            except Exception as e: print(f"\nAn error occurred: {e}"); break

# ==============================================================================
#  MAIN EXECUTION
# ==============================================================================
if assets_loaded:
    # Initialize our two engines with the loaded assets
    command_vectorizer = CommandVectorizer(vectorizer_knowledge_base)
    ml_prediction_engine = HybridPredictionPipeline(ml_model, ml_tokenizer, MAX_SEQUENCE_LENGTH)

    # Start the interactive session
    session = InteractiveIPSSession(command_vectorizer, ml_prediction_engine)
    session.start()
else:
    print("\n--- Session cannot start due to asset loading failure. ---")
    
