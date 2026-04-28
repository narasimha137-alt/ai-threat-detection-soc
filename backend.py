from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import os
import json

app = Flask(__name__)
from flask_cors import CORS

CORS(app, resources={r"/*": {"origins": "*"}})

# ================================
# LOAD MODELS (NO TRAINING HERE)
# ================================
try:
    model     = joblib.load("threat_model.pkl")
    scaler    = joblib.load("scaler.pkl")
    le_target = joblib.load("label_encoder.pkl")

    ATTACK_MODEL  = joblib.load("attack_model.pkl")
    ATTACK_SCALER = joblib.load("attack_scaler.pkl")
    ATTACK_LE     = joblib.load("attack_label_encoder.pkl")

    print("✅ Models loaded successfully")

except Exception as e:
    print(f"❌ Model loading failed: {e}")
    model = scaler = le_target = None
    ATTACK_MODEL = ATTACK_SCALER = ATTACK_LE = None


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
# HEALTH CHECK
# ================================
@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/")
def home():
    return {"message": "Backend running 🚀"}


# ================================
# PREDICT
# ================================
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()

        row = {f: data.get(f, 0) for f in FEATURES}
        df = pd.DataFrame([row])

        scaled = scaler.transform(df)

        pred  = model.predict(scaled)[0]
        proba = model.predict_proba(scaled)[0]

        threat = le_target.inverse_transform([pred])[0]

        response = {
            "threat": threat,
            "confidence": round(max(proba)*100, 2)
        }

        # Attack classifier
        if ATTACK_MODEL:
            atk_scaled = ATTACK_SCALER.transform(df)
            atk_pred = ATTACK_MODEL.predict(atk_scaled)[0]
            atk_type = ATTACK_LE.inverse_transform([atk_pred])[0]

            response["attack_type"] = atk_type

        return jsonify(response)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ================================
# RUN APP
# ================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
