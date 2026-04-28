const API_BASE_URL = "https://ai-threat-detection-soc-1.onrender.com";

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

export async function predictThreat(data: ThreatInput): Promise<ThreatResponse> {
  const res = await fetch(`${API_BASE_URL}/predict`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  });

  if (!res.ok) {
    throw new Error(`API error: ${res.status}`);
  }

  return res.json();
}

// API Status
export interface ApiStatus {
  gemini: boolean;
  ipstack: boolean;
  shap: boolean;
  aria: boolean;
  attack_classifier: boolean;
  isolation_forest: boolean;
}

export async function getApiStatus(): Promise<ApiStatus> {
  const res = await fetch(`${API_BASE_URL}/api-status`);
  if (!res.ok) throw new Error("Failed to fetch API status");
  const data = await res.json();
  return data.data;
}
