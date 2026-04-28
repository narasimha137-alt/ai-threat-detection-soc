const BASE_URL = import.meta.env.VITE_API_URL;
export async function fetchUbaData() {
  const res = await fetch(`${API_BASE_URL}/sample-connections`); // ✅ existing route

  if (!res.ok) {
    throw new Error("Failed to fetch UBA data");
  }

  const json = await res.json();
  return json.data;
}
