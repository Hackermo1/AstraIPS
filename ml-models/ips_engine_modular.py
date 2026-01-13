# File: ips_engine_modular.py
import sys
import os

# CRITICAL: Add user site-packages to sys.path FIRST (before any imports that need global packages)
user_site = os.path.expanduser("~/.local/lib/python3.11/site-packages")
if os.path.exists(user_site) and user_site not in sys.path:
    sys.path.insert(0, user_site)

# Also check PYTHONPATH environment variable
pythonpath = os.environ.get('PYTHONPATH', '')
if pythonpath:
    for path in pythonpath.split(':'):
        if path and os.path.exists(path) and path not in sys.path:
            sys.path.insert(0, path)

import warnings
# Suppress TensorFlow warnings
warnings.filterwarnings('ignore', category=UserWarning, module='tensorflow')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # Suppress INFO and WARNING messages

import pandas as pd
import re
# Try to import tensorflow (works with tensorflow-aarch64 on ARM)
try:
    import tensorflow as tf
except ImportError:
    try:
        # Try alternative import for ARM64
        import tensorflow_aarch64 as tf
    except ImportError:
        print("⚠️  TensorFlow not found - AI features disabled")
        tf = None
import pickle
# Import keras only if tensorflow is available
if tf is not None:
    try:
        from tensorflow.keras.preprocessing.sequence import pad_sequences
    except ImportError:
        try:
            import keras
            from keras.preprocessing.sequence import pad_sequences
        except ImportError as e:
            print(f"⚠️  Keras not available: {e}")
            print(f"   sys.path: {sys.path[:5]}...")  # Show first 5 paths
            pad_sequences = None
else:
    pad_sequences = None  # Will cause error if used, but allows script to load
import numpy as np
import json

# Add parent directory and ML directory to path for imports
base_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(base_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

from heuristic_flag_generator import HeuristicFlagGenerator
from user_flags_db import UserFlagsDB

class IPSEngine:
    def __init__(self, config):
        self.config = config
        self.device_profiles = {} # A dictionary to store device context
        self.assets_loaded = False
        
        # Initialize heuristic flag generator
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            excel_path = os.path.join(base_dir, 'phase1_feature_dataset1111111111 (2).xlsx')
            self.heuristic_generator = HeuristicFlagGenerator(excel_path)
            print("✅ Heuristic flag generator initialized")
        except Exception as e:
            print(f"⚠️  Heuristic flag generator initialization failed: {e}")
            self.heuristic_generator = None
        
        # Initialize user flags database - use session.db (centralized)
        try:
            # Use session.db from SESSION_LOG_DIR
            session_dir = os.environ.get('SESSION_LOG_DIR')
            if session_dir and os.path.exists(session_dir):
                db_path = os.path.join(session_dir, 'session.db')
            else:
                # Fallback: use session.db in current directory
                base_dir = os.path.dirname(os.path.abspath(__file__))
                db_path = os.path.join(base_dir, 'session.db')
            self.user_flags_db = UserFlagsDB(db_path)
            print("✅ User flags database initialized (using session.db)")
        except Exception as e:
            print(f"⚠️  User flags database initialization failed: {e}")
            self.user_flags_db = None
        
        self._load_assets()

        if self.assets_loaded:
            self.vectorizer = self._CommandVectorizer(self.vectorizer_knowledge_base)
            self.ml_predictor = self._HybridPredictionPipeline(
                self.ml_interpreter, # Pass the interpreter
                self.ml_tokenizer, 
                self.config['max_sequence_length']
            )

    def _load_assets(self):
        """Loads all necessary ML and vectorizer assets from paths specified in the config."""
        try:
            asset_paths = self.config['asset_paths']
            # Assume assets are in the same directory as this script for portability
            base_dir = os.path.dirname(os.path.abspath(__file__))

            # Load the tokenizer
            print("Loading tokenizer...")
            with open(os.path.join(base_dir, asset_paths['ml_tokenizer']), 'rb') as handle:
                self.ml_tokenizer = pickle.load(handle)
            print("✔️ Tokenizer loaded successfully.")

            # Load the TFLite model and allocate tensors.
            # Use TensorFlow's TFLite interpreter which supports Flex delegate
            if tf is None:
                print("❌ TensorFlow not available - cannot load ML model")
                self.assets_loaded = False
                return
                
            print("Loading TFLite model and allocating tensors...")
            try:
                # Try to load with Flex delegate support (for SELECT_TF_OPS)
                self.ml_interpreter = tf.lite.Interpreter(
                    model_path=os.path.join(base_dir, asset_paths['ml_model']),
                    experimental_preserve_all_tensors=False
                )
                # Try to enable Flex delegate if available
                try:
                    from tensorflow.lite.python.interpreter import load_delegate
                    flex_delegate = load_delegate('libtensorflowlite_flex.so')
                    if flex_delegate:
                        self.ml_interpreter.add_delegate(flex_delegate)
                        print("✔️ Flex delegate loaded for SELECT_TF_OPS support.")
                except Exception as flex_error:
                    # Flex delegate not available, but model might still work with full TensorFlow
                    print(f"⚠️  Flex delegate not available: {flex_error}")
                    print("   Using TensorFlow's built-in TFLite interpreter (should support SELECT_TF_OPS)")
                
                self.ml_interpreter.allocate_tensors()
                print("✔️ TFLite model loaded successfully.")
            except Exception as tflite_error:
                # Fallback: Try loading the original Keras model if TFLite fails
                print(f"⚠️  TFLite loading failed: {tflite_error}")
                print("   Attempting to load Keras model instead...")
                keras_model_path = os.path.join(base_dir, asset_paths['ml_model'].replace('.tflite', '.keras'))
                if os.path.exists(keras_model_path):
                    self.ml_model_keras = tf.keras.models.load_model(keras_model_path)
                    print("✔️ Keras model loaded successfully (using full TensorFlow).")
                    # Use Keras model directly (has predict() method)
                    self.ml_interpreter = self.ml_model_keras
                else:
                    # Try to find .keras file with same base name
                    base_name = os.path.splitext(asset_paths['ml_model'])[0]
                    keras_model_path = os.path.join(base_dir, base_name + '.keras')
                    if os.path.exists(keras_model_path):
                        self.ml_model_keras = tf.keras.models.load_model(keras_model_path)
                        print("✔️ Keras model loaded successfully (using full TensorFlow).")
                        self.ml_interpreter = self.ml_model_keras
                    else:
                        raise tflite_error
            
            # Load the Vectorizer's knowledge base
            print("Loading Vectorizer knowledge base...")
            self.vectorizer_knowledge_base = pd.read_excel(os.path.join(base_dir, asset_paths['vectorizer_data']), sheet_name='Sheet1')
            print("✔️ Vectorizer assets loaded successfully.")
            
            self.assets_loaded = True
        except Exception as e:
            print(f"❌ FATAL ERROR loading assets: {e}")
            self.assets_loaded = False

    def update_device_profile(self, profile_json):
        """Receives a JSON string, parses it, and stores the device profile."""
        try:
            profile = json.loads(profile_json)
            device_ip = profile.get("ip_address")
            if device_ip:
                self.device_profiles[device_ip] = profile
                print(f"  -> [PROFILE UPDATE] Context for device {device_ip} has been stored.")
        except json.JSONDecodeError:
            print("  -> [PROFILE WARNING] Received invalid JSON profile data.")

    def analyze(self, device_ip, command_payload):
        """The main public method to analyze a command, now with device context."""
        if not self.assets_loaded:
            return {"error": "Engine not initialized."}
        
        profile = self.device_profiles.get(device_ip, {})
        
        # Use device_ip as user_id for user-based tracking
        # This allows ML to track command history per IP address
        user_id = device_ip  # Use sender IP as user identifier
        command = command_payload
        
        # Check if command payload has explicit user info (for compatibility)
        match = re.search(r"user=(\S+)\s+command=(.*)", command_payload)
        if match:
            # If explicit user info provided, use it but still track by IP
            explicit_user = match.group(1)
            command = match.group(2)
            # Use IP-based user_id for ML tracking, but log explicit user if present
            print(f"    -> Analyzing for IP '{device_ip}' (user: {explicit_user}) with profile context: {profile}")
        else:
            print(f"    -> Analyzing for IP '{device_ip}' (user_id: {device_ip}) with profile context: {profile}")
        
        # STEP 1: Generate heuristic flag FIRST (FULL STRING CONVERSION)
        heuristic_flag = None
        if self.heuristic_generator:
            try:
                # Use FULL command string for heuristic analysis
                heuristic_flag = self.heuristic_generator.get_flag(command_payload)
                if heuristic_flag:
                    print(f"    -> Heuristic flag: {heuristic_flag} (source: heuristic)")
                    
                    # Store heuristic flag in database
                    if self.user_flags_db:
                        try:
                            self.user_flags_db.add_flag(
                                user_id=user_id,
                                device_ip=device_ip,
                                command=command_payload,
                                heuristic_flag=heuristic_flag
                            )
                        except Exception as db_error:
                            print(f"    ❌ Database error storing heuristic flag: {db_error}")
                            import traceback
                            traceback.print_exc()
                    else:
                        print(f"    ⚠️  user_flags_db is None - cannot store heuristic flag")
            except Exception as e:
                print(f"    ⚠️  Heuristic flag generation error: {e}")
                import traceback
                traceback.print_exc()
        
        # STEP 2: Run AI analysis (existing code)
        analysis_result = self.ml_predictor.predict(user_id, command)
        
        # STEP 3: Generate AI flag from AI analysis result
        ai_flag = None
        if analysis_result and 'is_malicious' in analysis_result:
            ai_flag = "MAL" if analysis_result.get('is_malicious') else "NOR"
            print(f"    -> AI flag: {ai_flag} (source: ai)")
            
            # Store AI flag in database (append to same row)
            if self.user_flags_db:
                try:
                    self.user_flags_db.add_flag(
                        user_id=user_id,
                        device_ip=device_ip,
                        command=command_payload,
                        ai_flag=ai_flag
                    )
                except Exception as e:
                    print(f"    ❌ AI flag storage error: {e}")
                    import traceback
                    traceback.print_exc()
            else:
                print(f"    ⚠️  user_flags_db is None - cannot store AI flag")
        
        return analysis_result

    class _CommandVectorizer:
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

    class _HybridPredictionPipeline:
        TRIPWIRE_RULES = {'wget ': 0.8, 'curl ': 0.8, 'nc ': 0.8, '/etc/shadow': 1.0, 'mimikatz': 1.0}
        
        def __init__(self, interpreter, tokenizer, max_len):
            self.interpreter = interpreter
            self.tokenizer = tokenizer
            self.max_len = max_len
            self.user_histories = {}
            
            # Check if we're using a Keras model (fallback) or TFLite interpreter
            self.use_keras = hasattr(interpreter, 'predict')
            
            if not self.use_keras:
                # Get input and output tensors for TFLite
                self.input_details = self.interpreter.get_input_details()
                self.output_details = self.interpreter.get_output_details()
            else:
                # For Keras model, we'll use predict() method directly
                self.input_details = None
                self.output_details = None

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
            
            if self.use_keras:
                # Use Keras model predict method
                prediction = self.interpreter.predict(padded, verbose=0)
                contextual_risk = float(prediction[0][0])
            else:
                # Use TFLite interpreter
                # Set the value of the input tensor.
                self.interpreter.set_tensor(self.input_details[0]['index'], padded.astype(np.float32))
                
                # Run the inference.
                self.interpreter.invoke()
                
                # Get the result.
                contextual_risk = self.interpreter.get_tensor(self.output_details[0]['index'])[0][0]
            
            final_risk = max(heuristic_risk, float(contextual_risk))
            reason = "Heuristic Match" if heuristic_risk > contextual_risk else "Contextual Pattern"
            
            is_malicious = final_risk > 0.5
            confidence = float(final_risk)

            return {
                "is_malicious": is_malicious,
                "confidence": confidence,
                "reason": reason
            }
