const API_BASE_URL = "https://ai-threat-detection-soc-1.onrender.com";

export async function fetchUbaData() {
  const res = await fetch(`${API_BASE_URL}/sample-connections`); // ✅ existing route

  if (!res.ok) {
    throw new Error("Failed to fetch UBA data");
  }

  const json = await res.json();
  return json.data;
}
