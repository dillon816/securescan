import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

// Affiche la progression du scan en cours
function Scan() {
  const navigate = useNavigate();
  const { state } = useLocation();
  const scanResults = state?.scanResults;

  const [progress, setProgress] = useState(0);
  const [tools, setTools] = useState([
    { name: "Semgrep", status: "running", icon: "🔍" },
    { name: "Bandit", status: "pending", icon: "🛡️" },
    { name: "TruffleHog", status: "pending", icon: "🐷" },
  ]);

  useEffect(() => {
    if (!scanResults) {
      navigate("/", { replace: true });
      return;
    }

    // Animation de progression
    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 90) return 90;
        return prev + 10;
      });
    }, 200);

    // Simulation de progression des outils
    const toolTimeout1 = setTimeout(() => {
      setTools((prev) =>
        prev.map((t) => (t.name === "Semgrep" ? { ...t, status: "done" } : t))
      );
    }, 400);

    const toolTimeout2 = setTimeout(() => {
      setTools((prev) =>
        prev.map((t) => (t.name === "Bandit" ? { ...t, status: "running" } : t))
      );
    }, 600);

    const toolTimeout3 = setTimeout(() => {
      setTools((prev) =>
        prev.map((t) => (t.name === "Bandit" ? { ...t, status: "done" } : t))
      );
      setTools((prev) =>
        prev.map((t) => (t.name === "TruffleHog" ? { ...t, status: "running" } : t))
      );
    }, 800);

    const toolTimeout4 = setTimeout(() => {
      setTools((prev) =>
        prev.map((t) => (t.name === "TruffleHog" ? { ...t, status: "done" } : t))
      );
      setProgress(100);
    }, 1000);

    const redirectTimeout = setTimeout(() => {
      navigate("/dashboard", { state: { scanResults } });
    }, 1500);

    return () => {
      clearInterval(progressInterval);
      clearTimeout(toolTimeout1);
      clearTimeout(toolTimeout2);
      clearTimeout(toolTimeout3);
      clearTimeout(toolTimeout4);
      clearTimeout(redirectTimeout);
    };
  }, [navigate, scanResults]);

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
          width: "min(600px, 100%)",
          backgroundColor: "#fff",
          borderRadius: 28,
          padding: 46,
          boxShadow: "0 12px 40px rgba(0,0,0,0.06)",
        }}
      >
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <h1 style={{ margin: 0, fontSize: 36, color: "#333" }}>Analyse en cours</h1>
          <p style={{ color: "#666", marginTop: 10, fontSize: 15 }}>
            SecureScan analyse votre projet avec plusieurs outils de sécurité
          </p>
        </div>

        {/* Barre de progression */}
        <div style={{ marginBottom: 32 }}>
          <div
            style={{
              width: "100%",
              height: 8,
              backgroundColor: "#e5e5e5",
              borderRadius: 999,
              overflow: "hidden",
            }}
          >
            <div
              style={{
                width: `${progress}%`,
                height: "100%",
                backgroundColor: "rgba(255, 182, 193, 0.8)",
                borderRadius: 999,
                transition: "width 0.3s ease",
              }}
            />
          </div>
          <p style={{ textAlign: "center", marginTop: 8, color: "#888", fontSize: 13 }}>
            {progress}% complété
          </p>
        </div>

        {/* Liste des outils */}
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {tools.map((tool) => (
            <div
              key={tool.name}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 14,
                padding: 16,
                borderRadius: 14,
                backgroundColor:
                  tool.status === "done"
                    ? "rgba(144, 238, 144, 0.1)"
                    : tool.status === "running"
                    ? "rgba(173, 216, 230, 0.1)"
                    : "#fafafa",
                border:
                  tool.status === "done"
                    ? "1px solid rgba(144, 238, 144, 0.3)"
                    : tool.status === "running"
                    ? "1px solid rgba(173, 216, 230, 0.3)"
                    : "1px solid #eee",
              }}
            >
              <span style={{ fontSize: 24 }}>{tool.icon}</span>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 700, fontSize: 15, color: "#333" }}>
                  {tool.name}
                </div>
                <div style={{ fontSize: 12, color: "#888", marginTop: 2 }}>
                  {tool.status === "done"
                    ? "Analyse terminée"
                    : tool.status === "running"
                    ? "Analyse en cours..."
                    : "En attente"}
                </div>
              </div>
              <div>
                {tool.status === "done" ? (
                  <span style={{ fontSize: 20 }}>✅</span>
                ) : tool.status === "running" ? (
                  <span
                    style={{
                      display: "inline-block",
                      width: 20,
                      height: 20,
                      border: "2px solid rgba(255, 182, 193, 0.5)",
                      borderTopColor: "rgba(255, 182, 193, 1)",
                      borderRadius: "50%",
                      animation: "spin 0.8s linear infinite",
                    }}
                  />
                ) : (
                  <span style={{ fontSize: 16, color: "#ccc" }}>⏳</span>
                )}
              </div>
            </div>
          ))}
        </div>

        <p style={{ marginTop: 24, textAlign: "center", color: "#999", fontSize: 13 }}>
          Redirection automatique vers le dashboard...
        </p>
      </div>

      <style>
        {`
          @keyframes spin {
            to { transform: rotate(360deg); }
          }
        `}
      </style>
    </div>
  );
}

export default Scan;