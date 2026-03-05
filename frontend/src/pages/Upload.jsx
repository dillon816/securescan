import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { scanZipAll, scanGitAll } from "../api/scans";

// Page principale pour lancer une analyse
export default function Upload() {
  const navigate = useNavigate();

  const [gitUrl, setGitUrl] = useState("");
  const [zipFile, setZipFile] = useState(null);
  const [githubToken, setGithubToken] = useState("");
  const [loading, setLoading] = useState(false);

  const canStart = useMemo(() => {
    const hasZip = !!zipFile;
    const hasGit = gitUrl.trim().length > 0;
    return (hasZip || hasGit) && !loading;
  }, [zipFile, gitUrl, loading]);
  
  const handleStart = async () => {
    const url = gitUrl.trim();
    if (!zipFile && !url) return;
  
    try {
      setLoading(true);
  
      const results = zipFile
        ? await scanZipAll(zipFile)
        : await scanGitAll(url, githubToken.trim() || null);
  
      navigate("/scan", { state: { scanResults: results } });
    } catch (e) {
      alert(`Erreur analyse: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        backgroundColor: "#f3f3f3",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 24,
      }}
    >
      <div
        style={{
          width: "min(980px, 100%)",
          backgroundColor: "#fff",
          borderRadius: 28,
          padding: 46,
          boxShadow: "0 12px 40px rgba(0,0,0,0.06)",
        }}
      >
        <h1 style={{ textAlign: "center", margin: 0, fontSize: 46 }}>
          SecureScan
        </h1>
        <p style={{ textAlign: "center", color: "#666", marginTop: 10 }}>
          Analysez la sécurité de votre projet facilement.
        </p>

        <div style={{ marginTop: 34 }}>
          <h3 style={{ marginBottom: 10 }}>URL Git (optionnel)</h3>
          <input
            type="text"
            placeholder="https://github.com/user/repo"
            value={gitUrl}
            onChange={(e) => setGitUrl(e.target.value)}
            style={{
              width: "100%",
              padding: 12,
              borderRadius: 12,
              border: "1px solid #ddd",
              outline: "none",
            }}
          />
          <p style={{ marginTop: 6, fontSize: 12, color: "#888" }}>
            Pour un repo <b>privé</b>, ajoute un token GitHub juste en dessous. Pour un repo public, le token est
            facultatif.
          </p>
        </div>

        <div style={{ marginTop: 18 }}>
          <h3 style={{ marginBottom: 8 }}>Token GitHub (optionnel)</h3>
          <input
            type="password"
            placeholder="ghp_… (nécessaire pour les repos privés)"
            value={githubToken}
            onChange={(e) => setGithubToken(e.target.value)}
            style={{
              width: "100%",
              padding: 12,
              borderRadius: 12,
              border: "1px solid #ddd",
              outline: "none",
            }}
          />
          <p style={{ marginTop: 6, fontSize: 12, color: "#888" }}>
            Le token n’est envoyé qu’à ton backend SecureScan pour cloner le repo et créer des analyses.
          </p>
        </div>

        <div style={{ textAlign: "center", margin: "28px 0", color: "#999" }}>
          — ou —
        </div>

        <div style={{ marginTop: 10 }}>
          <h3 style={{ marginBottom: 10 }}>Upload ZIP</h3>
          <input
            type="file"
            accept=".zip"
            onChange={(e) => setZipFile(e.target.files?.[0] ?? null)}
          />
          {zipFile && (
            <p style={{ marginTop: 10, color: "#666" }}>
              Fichier sélectionné : <b>{zipFile.name}</b>
            </p>
          )}
        </div>

        <div style={{ display: "flex", justifyContent: "center", marginTop: 40 }}>
          <button
            onClick={handleStart}
            disabled={!canStart}
            style={{
              backgroundColor: canStart ? "rgba(255, 182, 193, 0.25)" : "#e6e6e6",
              color: canStart ? "#c04c78" : "#999",
              border: canStart
                ? "1px solid rgba(255, 182, 193, 0.6)"
                : "1px solid #ddd",
              padding: "12px 22px",
              borderRadius: 14,
              fontSize: 14,
              cursor: canStart ? "pointer" : "not-allowed",
              minWidth: 170,
            }}
          >
            {loading ? "Analyse en cours..." : "Lancer l’analyse"}
          </button>
        </div>
      </div>
    </div>
  );
}