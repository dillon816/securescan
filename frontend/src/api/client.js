const API_BASE = process.env.REACT_APP_API_URL || "http://localhost:8001";

async function parseError(res) {
  try {
    const data = await res.json();
    return data?.detail ? JSON.stringify(data.detail) : JSON.stringify(data);
  } catch {
    return await res.text();
  }
}

// Envoie une requête POST avec du JSON
export async function postJson(path, body) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}

// Envoie une requête POST avec FormData
export async function postFormData(path, formData) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    body: formData,
  });
  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}

// Envoie une requête GET et récupère du JSON
export async function getJson(path) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "GET",
  });
  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}