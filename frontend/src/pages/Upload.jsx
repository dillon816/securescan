import { useState } from "react";
import { useNavigate } from "react-router-dom";

function Upload() {
  const navigate = useNavigate();
  const [gitUrl, setGitUrl] = useState("");
  const [zipFile, setZipFile] = useState(null);

  const canStart = gitUrl.trim().length > 0 || zipFile !== null;

  const handleStart = () => {
    navigate("/scan");
  };

  return (
    <div
      style={{
        maxWidth: 600,
        margin: "80px auto",
        padding: 40,
        backgroundColor: "white",
        borderRadius: 24,
        boxShadow: "0 8px 30px rgba(0,0,0,0.05)",
      }}
    >
      <h1 style={{ textAlign: "center", marginBottom: 10 }}>SecureScan</h1>

      <p style={{ textAlign: "center", marginBottom: 40, color: "#666" }}>
        Analysez la sécurité de votre projet facilement.
      </p>

      <h3>URL Git</h3>
      <input
        type="text"
        value={gitUrl}
        onChange={(e) => {
          setGitUrl(e.target.value);
          if (e.target.value.trim().length > 0) setZipFile(null);
        }}
        placeholder="https://github.com/user/repo"
        style={{ width: "100%", marginBottom: 25 }}
      />

      <div style={{ textAlign: "center", margin: "25px 0", color: "#999" }}>
        — ou —
      </div>

      <h3>Upload ZIP</h3>
      <input
        type="file"
        accept=".zip"
        onChange={(e) => {
          const f = e.target.files?.[0] ?? null;
          setZipFile(f);
          if (f) setGitUrl("");
        }}
      />

      <div style={{ textAlign: "center", marginTop: 40 }}>
        <button
          onClick={handleStart}
          disabled={!canStart}
          style={{
            backgroundColor: canStart ? "rgba(255, 182, 193, 0.25)" : "#e0e0e0",
            color: canStart ? "#c04c78" : "#999",
            border: canStart
              ? "1px solid rgba(255, 182, 193, 0.6)"
              : "1px solid #ddd",
            padding: "12px 22px",
            borderRadius: 14,
            fontSize: 14,
            cursor: canStart ? "pointer" : "not-allowed",
            transition: "0.2s ease",
          }}
        >
          Lancer l’analyse
        </button>
      </div>
    </div>
  );
}

export default Upload;