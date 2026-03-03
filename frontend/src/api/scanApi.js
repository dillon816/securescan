// src/api/scanApi.js
import { postJson, postFormData } from "../services/api";

// Helpers
function normalizeSettled(toolName, settled) {
  if (settled.status === "fulfilled") return settled.value;
  return { tool: toolName, error: settled.reason?.message || String(settled.reason) };
}

// ZIP
export async function scanZipAll(file) {
  const fd = new FormData();
  fd.append("file", file);

  const [semgrep, bandit, trufflehog] = await Promise.allSettled([
    postFormData("/scan/semgrep", fd),
    postFormData("/scan/bandit", fd),
    postFormData("/scan/trufflehog", fd),
  ]);

  return {
    semgrep: normalizeSettled("semgrep", semgrep),
    bandit: normalizeSettled("bandit", bandit),
    trufflehog: normalizeSettled("trufflehog", trufflehog),
  };
}

// GIT
export async function scanGitAll(repo_url) {
  const [semgrep, bandit, trufflehog] = await Promise.allSettled([
    postJson("/scan/semgrep/git", { repo_url }),
    postJson("/scan/bandit/git", { repo_url }),
    postJson("/scan/trufflehog/git", { repo_url }),
  ]);

  return {
    semgrep: normalizeSettled("semgrep", semgrep),
    bandit: normalizeSettled("bandit", bandit),
    trufflehog: normalizeSettled("trufflehog", trufflehog),
  };
}