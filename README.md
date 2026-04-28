# 🛡️ AI Threat Detection SOC Dashboard

A complete, full-stack Security Operations Center (SOC) dashboard powered by Machine Learning and AI. This system analyzes network traffic in real-time to detect, classify, and explain cyber threats using advanced data science.

![SOC Dashboard Preview](https://via.placeholder.com/1000x500.png?text=AI+Threat+Detection+SOC+Dashboard)

## ✨ Core Features
*   **Real-Time Threat Detection**: Uses a Random Forest classifier trained on the NSL-KDD dataset to detect attacks (DoS, Probe, R2L, U2R).
*   **Zero-Day Anomaly Engine**: Employs an Isolation Forest to flag "Zero-Day" novel attacks that don't match known signatures.
*   **Explainable AI (SHAP)**: Instantly breaks down exactly *why* an attack was flagged (e.g., showing high source bytes or strange flags).
*   **Global Geolocation Map**: Real-time pulsing world map showing the geographical origin of attacks using the IPStack API.
*   **Automated AI Reporting**: Uses Gemini 1.5 Flash to generate professional executive summaries and incident response actions for detected threats.
*   **Simulation Runner**: Test the dashboard using real historical network data.
---
## 🧠 Technology Stack
*   **Frontend**: React (Vite), TypeScript, Tailwind CSS, Recharts, Framer Motion
*   **Backend**: Python, Flask, Scikit-Learn (Random Forest, Isolation Forest)
*   **APIs**: Google Gemini (NLP Reports), IPStack (Geolocation)
