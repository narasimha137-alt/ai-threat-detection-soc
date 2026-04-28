const API_BASE_URL = "https://ai-threat-detection-soc-1.onrender.com";

export async function predictThreat(data: any) {
  const res = await fetch(`${API_BASE_URL}/predict`, {   // ✅ CORRECT
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  });

  if (!res.ok) {
    throw new Error("API error");
  }

  return res.json();
}
