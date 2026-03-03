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

// Envoie un fichieir ZIP au backend pour lancer l'analayse Bandit
export async function scanBanditZip(zipFile) {
  const formData = new FormData();
  formData.append("file", zipFile);

  const res = await fetch(`${API_BASE}/scan/bandit`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}

// Envoie un fichieir ZIP au backend pour lancer l'analayse TruffleHog
export async function scanTrufflehogZip(zipFile) {
  const formData = new FormData();
  formData.append("file", zipFile);

  const res = await fetch(`${API_BASE}/scan/trufflehog`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}

// Envoie une URL Git au backend pour analyser le repository (Semgrep)
export async function scanSemgrepGit(gitUrl) {
  const res = await fetch(`${API_BASE}/scan/semgrep/git`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo_url: gitUrl }),
  });

  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}

// Envoie une URL Git au backend pour analyser le repository (Bandit)
export async function scanBanditGit(gitUrl) {
  const res = await fetch(`${API_BASE}/scan/bandit/git`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo_url: gitUrl }),
  });

  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}

// Envoie une URL Git au backend pour analyser le repository (TruffleHog)
export async function scanTrufflehogGit(gitUrl) {
  const res = await fetch(`${API_BASE}/scan/trufflehog/git`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo_url: gitUrl }),
  });

  if (!res.ok) throw new Error(await parseError(res));
  return res.json();
}

// Lance les 3 analyseurs sur un ZIP et regroupe les résultats
export async function scanZipAll(zipFile) {
  const [semgrep, bandit, trufflehog] = await Promise.allSettled([
    scanSemgrepZip(zipFile),
    scanBanditZip(zipFile),
    scanTrufflehogZip(zipFile),
  ]);

  return {
    semgrepResult: semgrep.status === "fulfilled" ? semgrep.value : { tool: "semgrep", error: String(semgrep.reason?.message || semgrep.reason) },
    banditResult: bandit.status === "fulfilled" ? bandit.value : { tool: "bandit", error: String(bandit.reason?.message || bandit.reason) },
    trufflehogResult: trufflehog.status === "fulfilled" ? trufflehog.value : { tool: "trufflehog", error: String(trufflehog.reason?.message || trufflehog.reason) },
  };
}

// Lance les 3 analyseurs sur une URL Git et regroupe les résultats
export async function scanGitAll(gitUrl) {
  const [semgrep, bandit, trufflehog] = await Promise.allSettled([
    scanSemgrepGit(gitUrl),
    scanBanditGit(gitUrl),
    scanTrufflehogGit(gitUrl),
  ]);

  return {
    semgrepResult: semgrep.status === "fulfilled" ? semgrep.value : { tool: "semgrep", error: String(semgrep.reason?.message || semgrep.reason) },
    banditResult: bandit.status === "fulfilled" ? bandit.value : { tool: "bandit", error: String(bandit.reason?.message || bandit.reason) },
    trufflehogResult: trufflehog.status === "fulfilled" ? trufflehog.value : { tool: "trufflehog", error: String(trufflehog.reason?.message || trufflehog.reason) },
  };
}