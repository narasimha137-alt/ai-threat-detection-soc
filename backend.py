from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import os

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ================================
# LOAD MODELS (SAFE)
# ================================
model = scaler = le_target = None
ATTACK_MODEL = ATTACK_SCALER = ATTACK_LE = None

try:
    model     = joblib.load("threat_model.pkl")
    scaler    = joblib.load("scaler.pkl")
    le_target = joblib.load("label_encoder.pkl")

    # Optional attack models
    if os.path.exists("attack_model.pkl"):
        ATTACK_MODEL  = joblib.load("attack_model.pkl")
        ATTACK_SCALER = joblib.load("attack_scaler.pkl")
        ATTACK_LE     = joblib.load("attack_label_encoder.pkl")

    print("✅ Models loaded successfully")

except Exception as e:
    print(f"❌ Model loading failed: {e}")


# ================================
# FEATURES
# ================================
FEATURES = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
    "root_shell","su_attempted","num_root","num_file_creations","num_shells",
    "num_access_files","num_outbound_cmds","is_host_login","is_guest_login",
    "count","srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
    "same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
    "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate"
]


# ================================
# HEALTH
# ================================
@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/")
def home():
    return {"message": "Backend running 🚀"}


# ================================
# API STATUS (FIXED)
# ================================
@app.route("/api-status", methods=["GET"])
def api_status():
    try:
        return jsonify({
            "success": True,
            "data": {
                "model_loaded": model is not None,
                "attack_model_loaded": ATTACK_MODEL is not None,
            },
            "error": None
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e), "data": None}), 500


# ================================
# PREDICT
# ================================
@app.route("/predict", methods=["POST"])
def predict():
    try:
        if model is None or scaler is None:
            return jsonify({"error": "Model not loaded"}), 500

        data = request.get_json()

        row = {f: data.get(f, 0) for f in FEATURES}
        df = pd.DataFrame([row])

        scaled = scaler.transform(df)

        pred  = model.predict(scaled)[0]
        proba = model.predict_proba(scaled)[0]

        threat = le_target.inverse_transform([pred])[0]

        response = {
            "threat": threat,
            "confidence": round(float(max(proba)) * 100, 2),
            "attack_type": "Unknown",
            "is_anomalous": False
        }

        # Attack classifier (safe)
        if ATTACK_MODEL and ATTACK_SCALER and ATTACK_LE:
            try:
                atk_scaled = ATTACK_SCALER.transform(df)
                atk_pred = ATTACK_MODEL.predict(atk_scaled)[0]
                atk_type = ATTACK_LE.inverse_transform([atk_pred])[0]
                response["attack_type"] = atk_type
            except Exception as e:
                print(f"Attack model error: {e}")

        return jsonify(response)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ================================
# RUN
# ================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
