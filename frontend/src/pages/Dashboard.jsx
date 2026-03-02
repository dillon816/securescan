import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

function SeverityBadge({ severity }) {
  const styles = {
    Critical: {
      bg: "rgba(255, 182, 193, 0.35)",
      border: "rgba(255, 182, 193, 0.8)",
      text: "#b13a62",
    },
    High: {
      bg: "rgba(255, 215, 130, 0.35)",
      border: "rgba(255, 215, 130, 0.8)",
      text: "#9b5b00",
    },
    Medium: {
      bg: "rgba(180, 210, 255, 0.35)",
      border: "rgba(180, 210, 255, 0.8)",
      text: "#2456a6",
    },
    Low: {
      bg: "rgba(190, 255, 210, 0.35)",
      border: "rgba(190, 255, 210, 0.8)",
      text: "#1f7a44",
    },
  };

  const s = styles[severity] ?? {
    bg: "rgba(220, 220, 220, 0.6)",
    border: "rgba(220, 220, 220, 1)",
    text: "#555",
  };

  return (
    <span
      style={{
        display: "inline-block",
        padding: "6px 10px",
        borderRadius: 999,
        backgroundColor: s.bg,
        border: `1px solid ${s.border}`,
        color: s.text,
        fontSize: 13,
        fontWeight: 600,
      }}
    >
      {severity}
    </span>
  );
}

function Dashboard() {
  const navigate = useNavigate();
  const score = 72;

  const findings = useMemo(
    () => [
      { id: 1, title: "SQL Injection", severity: "High", owasp: "A05", file: "app.py" },
      { id: 2, title: "Hardcoded Secret", severity: "Critical", owasp: "A04", file: "config.js" },
      { id: 3, title: "Outdated Dependency", severity: "Medium", owasp: "A03", file: "package.json" },
      { id: 4, title: "Missing Security Headers", severity: "Low", owasp: "A02", file: "server.py" },
    ],
    []
  );

  const [severityFilter, setSeverityFilter] = useState("All");
  const [owaspFilter, setOwaspFilter] = useState("All");

  const owaspOptions = useMemo(() => {
    const set = new Set(findings.map((f) => f.owasp));
    return Array.from(set).sort();
  }, [findings]);

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const okSeverity = severityFilter === "All" || f.severity === severityFilter;
      const okOwasp = owaspFilter === "All" || f.owasp === owaspFilter;
      return okSeverity && okOwasp;
    });
  }, [findings, severityFilter, owaspFilter]);

  return (
    <div style={{ maxWidth: 1100, margin: "40px auto", padding: "0 20px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
        <h1 style={{ marginBottom: 20 }}>Dashboard</h1>

        <button
          onClick={() => navigate("/fixes")}
          style={{
            height: 44,
            alignSelf: "center",
            backgroundColor: "rgba(255, 182, 193, 0.25)",
            color: "#c04c78",
            border: "1px solid rgba(255, 182, 193, 0.6)",
            padding: "10px 14px",
            borderRadius: 14,
            cursor: "pointer",
          }}
        >
          Voir corrections
        </button>
      </div>

      <div
        style={{
          backgroundColor: "white",
          padding: 28,
          borderRadius: 22,
          boxShadow: "0 8px 30px rgba(0,0,0,0.05)",
          marginBottom: 24,
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 20,
        }}
      >
        <div>
          <h2 style={{ margin: 0 }}>Score global</h2>
          <p style={{ margin: "10px 0 0", color: "#666" }}>
            {filteredFindings.length} vulnérabilité(s) affichée(s) (sur {findings.length})
          </p>
        </div>

        <div
          style={{
            fontSize: 42,
            fontWeight: 800,
            color: "#c04c78",
            backgroundColor: "rgba(255, 182, 193, 0.18)",
            border: "1px solid rgba(255, 182, 193, 0.45)",
            padding: "14px 18px",
            borderRadius: 18,
            minWidth: 150,
            textAlign: "center",
          }}
        >
          {score}/100
        </div>
      </div>

      <div
        style={{
          backgroundColor: "white",
          padding: 28,
          borderRadius: 22,
          boxShadow: "0 8px 30px rgba(0,0,0,0.05)",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            gap: 16,
            flexWrap: "wrap",
            alignItems: "center",
          }}
        >
          <h2 style={{ marginTop: 0, marginBottom: 0 }}>Vulnérabilités détectées</h2>

          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              style={{
                padding: "10px 12px",
                borderRadius: 12,
                border: "1px solid #ddd",
                backgroundColor: "#fff",
              }}
            >
              <option value="All">Toutes les sévérités</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>

            <select
              value={owaspFilter}
              onChange={(e) => setOwaspFilter(e.target.value)}
              style={{
                padding: "10px 12px",
                borderRadius: 12,
                border: "1px solid #ddd",
                backgroundColor: "#fff",
              }}
            >
              <option value="All">Toutes les catégories OWASP</option>
              {owaspOptions.map((o) => (
                <option key={o} value={o}>
                  {o}
                </option>
              ))}
            </select>

            <button
              onClick={() => {
                setSeverityFilter("All");
                setOwaspFilter("All");
              }}
              style={{
                backgroundColor: "rgba(255, 182, 193, 0.25)",
                color: "#c04c78",
                border: "1px solid rgba(255, 182, 193, 0.6)",
                padding: "10px 14px",
                borderRadius: 14,
                cursor: "pointer",
              }}
            >
              Réinitialiser
            </button>
          </div>
        </div>

        <table style={{ width: "100%", marginTop: 16, borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ textAlign: "left", borderBottom: "1px solid #eee" }}>
              <th style={{ padding: "12px 10px" }}>Titre</th>
              <th style={{ padding: "12px 10px" }}>Sévérité</th>
              <th style={{ padding: "12px 10px" }}>OWASP</th>
              <th style={{ padding: "12px 10px" }}>Fichier</th>
            </tr>
          </thead>

          <tbody>
            {filteredFindings.map((item) => (
              <tr key={item.id} style={{ borderBottom: "1px solid #f2f2f2" }}>
                <td style={{ padding: "12px 10px" }}>{item.title}</td>
                <td style={{ padding: "12px 10px" }}>
                  <SeverityBadge severity={item.severity} />
                </td>
                <td style={{ padding: "12px 10px", fontWeight: 600, color: "#444" }}>
                  {item.owasp}
                </td>
                <td style={{ padding: "12px 10px", color: "#555" }}>{item.file}</td>
              </tr>
            ))}

            {filteredFindings.length === 0 && (
              <tr>
                <td colSpan={4} style={{ padding: 16, color: "#777" }}>
                  Aucun résultat pour ces filtres.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default Dashboard;