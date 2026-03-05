import { postJson, postFormData } from "./client";

// Helpers
function normalizeSettled(toolName, settled) {
  if (settled.status === "fulfilled") return settled.value;
  return { tool: toolName, error: settled.reason?.message || String(settled.reason) };
}

// ZIP: endpoints individuels (si tu en as encore besoin)
export async function scanSemgrepZip(zipFile) {
  const fd = new FormData();
  fd.append("file", zipFile);
  return postFormData("/scan/semgrep", fd);
}

export async function scanBanditZip(zipFile) {
  const fd = new FormData();
  fd.append("file", zipFile);
  return postFormData("/scan/bandit", fd);
}

export async function scanTrufflehogZip(zipFile) {
  const fd = new FormData();
  fd.append("file", zipFile);
  return postFormData("/scan/trufflehog", fd);
}

// GIT: endpoints individuels
export async function scanSemgrepGit(repo_url) {
  return postJson("/scan/semgrep/git", { repo_url });
}

export async function scanBanditGit(repo_url) {
  return postJson("/scan/bandit/git", { repo_url });
}

export async function scanTrufflehogGit(repo_url) {
  return postJson("/scan/trufflehog/git", { repo_url });
}

// ALL (ZIP)
export async function scanZipAll(file) {
  const fd = new FormData();
  fd.append("file", file);

  const [semgrep, bandit, trufflehog] = await Promise.allSettled([
    postFormData("/scan/semgrep", fd),
    postFormData("/scan/bandit", fd),
    postFormData("/scan/trufflehog", fd),
  ]);

  return {
    semgrepResult: normalizeSettled("semgrep", semgrep),
    banditResult: normalizeSettled("bandit", bandit),
    trufflehogResult: normalizeSettled("trufflehog", trufflehog),
  };
}

// ALL (GIT)
export async function scanGitAll(repo_url) {
  const [semgrep, bandit, trufflehog] = await Promise.allSettled([
    postJson("/scan/semgrep/git", { repo_url }),
    postJson("/scan/bandit/git", { repo_url }),
    postJson("/scan/trufflehog/git", { repo_url }),
  ]);

  return {
    semgrepResult: normalizeSettled("semgrep", semgrep),
    banditResult: normalizeSettled("bandit", bandit),
    trufflehogResult: normalizeSettled("trufflehog", trufflehog),
  };
}