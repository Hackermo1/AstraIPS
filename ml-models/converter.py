# converter.py
import tensorflow as tf
import os

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KERAS_MODEL_PATH = os.path.join(BASE_DIR, 'ips_model.keras')
TFLITE_MODEL_PATH = os.path.join(BASE_DIR, 'ips_model.tflite')

print("--- Keras to TensorFlow Lite Converter ---")

# 1. Load the trained Keras model
print(f"🚀 Loading Keras model from: {KERAS_MODEL_PATH}")
try:
    model = tf.keras.models.load_model(KERAS_MODEL_PATH)
    print("✅ Keras model loaded successfully.")
except Exception as e:
    print(f"❌ FATAL: Could not load .keras model. Error: {e}")
    print("   Ensure 'ips_model.keras' is in the same directory.")
    exit(1)

# 2. Convert the model to TensorFlow Lite format
print("🔄 Converting model to TensorFlow Lite format...")
converter = tf.lite.TFLiteConverter.from_keras_model(model)
# Enable SELECT_TF_OPS for models with operations not fully supported in TFLite
converter.target_spec.supported_ops = [tf.lite.OpsSet.TFLITE_BUILTINS, tf.lite.OpsSet.SELECT_TF_OPS]
converter._experimental_lower_tensor_list_ops = False
tflite_model = converter.convert()
print("✅ Model converted successfully.")

# 3. Save the new .tflite model
print(f"💾 Saving TensorFlow Lite model to: {TFLITE_MODEL_PATH}")
with open(TFLITE_MODEL_PATH, 'wb') as f:
    f.write(tflite_model)

print("\n🎉 --- Conversion Complete! --- 🎉")
print(f"Your new model is ready at: {TFLITE_MODEL_PATH}")
print("\nYou can now uninstall the full 'tensorflow' package and install the lightweight 'tflite-runtime'.")
