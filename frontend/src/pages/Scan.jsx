import { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";

// Page d'attente affichant le statut du scan avant la redirection vers le dashboard
function Scan() {
  const navigate = useNavigate();
  const { state } = useLocation();
  const scanResults = state?.scanResults;

  useEffect(() => {
    if (!scanResults) {
      navigate("/", { replace: true });
      return;
    }

    const t = setTimeout(() => {
      navigate("/dashboard", { state: { scanResults } });
    }, 1200);

    return () => clearTimeout(t);
  }, [navigate, scanResults]);

  return (
    <div style={{ maxWidth: 900, margin: "40px auto", padding: "0 20px" }}>
      <div
        style={{
          backgroundColor: "white",
          padding: 28,
          borderRadius: 22,
          boxShadow: "0 8px 30px rgba(0,0,0,0.05)",
        }}
      >
        <h1 style={{ marginTop: 0 }}>Analyse en cours…</h1>
        <p style={{ color: "#666", marginTop: 6 }}>
          On lance les outils et on prépare les résultats.
        </p>

        <div
          style={{
            marginTop: 18,
            border: "1px solid #eee",
            borderRadius: 18,
            padding: 18,
            backgroundColor: "#fafafa",
          }}
        >
          <p style={{ margin: 0, padding: "8px 0" }}>Semgrep ✅</p>
          <p style={{ margin: 0, padding: "8px 0" }}>TruffleHog ⏳</p>
          <p style={{ margin: 0, padding: "8px 0" }}>pip-audit ⏳</p>
        </div>

        <p style={{ marginTop: 16, color: "#999", fontSize: 13 }}>
          (Redirection automatique vers le dashboard.)
        </p>
      </div>
    </div>
  );
}

export default Scan;