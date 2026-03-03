const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8001";

// Fonction utilitaire pour extraire un message d'erreur lisible depuis la réponse API
async function parseError(res) {
  try {
    const data = await res.json();
    return data?.detail ? JSON.stringify(data.detail) : JSON.stringify(data);
  } catch {
    return await res.text();
  }
}

// Envoie un fichieir ZIP au backend pour lancer l'analayse Semgrep
export async function scanSemgrepZip(zipFile) {
  const formData = new FormData();
  formData.append("file", zipFile);

  const res = await fetch(`${API_BASE}/scan/semgrep`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}

// Envoie une URL Git au backend pour analyser le repository 
export async function scanGit(gitUrl) {
  const res = await fetch(`${API_BASE}/scan/git`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo_url: gitUrl }),
  });

  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}