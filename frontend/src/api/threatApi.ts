const BASE_URL = import.meta.env.VITE_API_URL;
// ===== TYPES =====
export interface ThreatInput {
  [key: string]: number;
}

export interface ThreatResponse {
  threat: "LOW" | "MEDIUM" | "HIGH";
  confidence: number;
  probabilities?: Record<string, number>;
  attack_type?: string;
  attack_probabilities?: Record<string, number>;
  shap_values?: any[];
  is_anomalous?: boolean;
  anomaly_score?: number;
  location?: any;
}

export async function uploadDataset(file: File) {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${BASE_URL}/upload-dataset`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) {
    throw new Error("Upload failed");
  }

  return res.json();
}

export interface ApiStatus {
  gemini: boolean;
  ipstack: boolean;
  shap: boolean;
  aria: boolean;
  attack_classifier: boolean;
  isolation_forest: boolean;
}

// ===== PREDICT =====
export async function predictThreat(data: ThreatInput): Promise<ThreatResponse> {
  const res = await fetch(`${API_BASE_URL}/predict`, {   // ✅ CORRECT ROUTE
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Prediction failed: ${res.status} - ${text}`);
  }

  return res.json();
}

// ===== API STATUS =====
export async function getApiStatus(): Promise<ApiStatus> {
  const res = await fetch(`${API_BASE_URL}/api-status`);  // ✅ CORRECT

  if (!res.ok) {
    throw new Error("Failed to fetch API status");
  }

  const json = await res.json();
  return json.data;
}
