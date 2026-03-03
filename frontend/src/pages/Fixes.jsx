import { useMemo, useState } from "react";

function SeverityBadge({ severity }) {
  const styles = {
    Critical: {
      bg: "rgba(255, 99, 132, 0.18)",
      border: "rgba(255, 99, 132, 0.6)",
      text: "#b00020",
    },
    High: {
      bg: "rgba(255, 159, 64, 0.18)",
      border: "rgba(255, 159, 64, 0.6)",
      text: "#a04e00",
    },
    Medium: {
      bg: "rgba(54, 162, 235, 0.18)",
      border: "rgba(54, 162, 235, 0.6)",
      text: "#1f5fa8",
    },
    Low: {
      bg: "rgba(75, 192, 192, 0.18)",
      border: "rgba(75, 192, 192, 0.6)",
      text: "#1c7a7a",
    },
  };

  const s = styles[severity] ?? {
    bg: "rgba(220,220,220,0.3)",
    border: "#ddd",
    text: "#555",
  };

  return (
    <span
      style={{
        display: "inline-block",
        padding: "6px 12px",
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

function OwaspBadge({ code }) {
  return (
    <span
      style={{
        display: "inline-block",
        padding: "6px 12px",
        borderRadius: 999,
        backgroundColor: "rgba(0,0,0,0.05)",
        border: "1px solid #ddd",
        fontSize: 13,
        fontWeight: 600,
        color: "#444",
      }}
    >
      {code}
    </span>
  );
}

function CodeBox({ text }) {
  return (
    <pre
      style={{
        margin: 0,
        padding: 14,
        borderRadius: 14,
        backgroundColor: "#fafafa",
        border: "1px solid #eee",
        overflowX: "auto",
        fontSize: 13,
        lineHeight: 1.4,
      }}
    >
      {text}
    </pre>
  );
}

function Fixes() {
  const fixes = useMemo(
    () => [
      {
        id: "fix-1",
        title: "Remplacer un secret hardcodé par une variable d’environnement",
        file: "config.js",
        owasp: "A04",
        severity: "Critical",
        before: 'const API_KEY = "12345-SECRET";',
        after: "const API_KEY = process.env.API_KEY;",
      },
      {
        id: "fix-2",
        title: "Mettre à jour une dépendance vulnérable",
        file: "package.json",
        owasp: "A03",
        severity: "Medium",
        before: '"lodash": "4.17.19"',
        after: '"lodash": "4.17.21"',
      },
      {
        id: "fix-3",
        title: "Ajouter des headers de sécurité (exemple)",
        file: "server.py",
        owasp: "A02",
        severity: "Low",
        before: "app = FastAPI()",
        after: "app = FastAPI()\n# + middleware headers sécurité (exemple)",
      },
    ],
    []
  );

  const [selected, setSelected] = useState(() => new Set());
  const [status, setStatus] = useState("idle"); 

  const toggle = (id) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const selectedCount = selected.size;

  const canApply = selectedCount > 0 && status !== "applying";

  const handleApply = () => {
    if (!canApply) return;
    setStatus("applying");
    setTimeout(() => setStatus("done"), 900);
  };

  const handleDownloadReport = () => {
    const lines = [];
    lines.push("SecureScan - Rapport (DEMO)");
    lines.push(`Date: ${new Date().toLocaleString()}`);
    lines.push("");
    lines.push("Corrections sélectionnées:");
    fixes
      .filter((f) => selected.has(f.id))
      .forEach((f) =>
        lines.push(`- ${f.title} | ${f.file} | ${f.owasp} | ${f.severity}`)
      );

    if (selectedCount === 0) lines.push("- (Aucune)");

    const blob = new Blob([lines.join("\n")], {
      type: "text/plain;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = "securescan_report_demo.txt";
    a.click();

    URL.revokeObjectURL(url);
  };

  return (
    <div style={{ maxWidth: 1100, margin: "40px auto", padding: "0 20px" }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          gap: 16,
          flexWrap: "wrap",
          alignItems: "center",
        }}
      >
        <div>
          <h1 style={{ marginBottom: 6 }}>Corrections & Rapport</h1>
          <p style={{ marginTop: 0, color: "#666" }}>
            Sélectionne des corrections à appliquer, puis génère un rapport.
          </p>
        </div>

        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          <button
            onClick={handleApply}
            disabled={!canApply}
            style={{
              backgroundColor: canApply ? "rgba(255, 182, 193, 0.25)" : "#e0e0e0",
              color: canApply ? "#c04c78" : "#999",
              border: canApply
                ? "1px solid rgba(255, 182, 193, 0.6)"
                : "1px solid #ddd",
              padding: "10px 14px",
              borderRadius: 14,
              cursor: canApply ? "pointer" : "not-allowed",
            }}
          >
            {status === "applying" ? "Application..." : "Appliquer corrections"}
          </button>

          <button
            onClick={handleDownloadReport}
            style={{
              backgroundColor: "rgba(255, 182, 193, 0.18)",
              color: "#c04c78",
              border: "1px solid rgba(255, 182, 193, 0.45)",
              padding: "10px 14px",
              borderRadius: 14,
              cursor: "pointer",
            }}
          >
            Télécharger rapport (demo)
          </button>
        </div>
      </div>

      {status === "done" && (
        <div
          style={{
            marginTop: 14,
            padding: 14,
            backgroundColor: "white",
            borderRadius: 18,
            boxShadow: "0 8px 30px rgba(0,0,0,0.05)",
            border: "1px solid #f1f1f1",
          }}
        >
          ✅ Corrections appliquées.
        </div>
      )}

      <div
        style={{
          marginTop: 18,
          backgroundColor: "white",
          padding: 24,
          borderRadius: 22,
          boxShadow: "0 8px 30px rgba(0,0,0,0.05)",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            gap: 12,
            flexWrap: "wrap",
            alignItems: "center",
          }}
        >
          <h2 style={{ marginTop: 0, marginBottom: 0 }}>Corrections proposées</h2>
          <p style={{ margin: 0, color: "#666" }}>
            Sélectionnées : <b>{selectedCount}</b> / {fixes.length}
          </p>
        </div>

        <div style={{ marginTop: 18, display: "grid", gap: 16 }}>
          {fixes.map((fix) => {
            const checked = selected.has(fix.id);

            return (
              <div
                key={fix.id}
                style={{
                  border: "1px solid #eee",
                  borderRadius: 18,
                  padding: 16,
                  backgroundColor: checked
                    ? "rgba(255, 182, 193, 0.08)"
                    : "white",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    gap: 12,
                    flexWrap: "wrap",
                  }}
                >
                  <label
                    style={{
                      display: "flex",
                      gap: 10,
                      alignItems: "flex-start",
                      cursor: "pointer",
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggle(fix.id)}
                      style={{ marginTop: 3 }}
                    />
                    <div>
                      <div style={{ fontWeight: 700 }}>{fix.title}</div>
                      <div style={{ marginTop: 6, color: "#666" }}>
                        Fichier : <b>{fix.file}</b>
                      </div>
                    </div>
                  </label>

                  <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                    <OwaspBadge code={fix.owasp} />
                    <SeverityBadge severity={fix.severity} />
                  </div>
                </div>

                <div
                  style={{
                    marginTop: 14,
                    display: "grid",
                    gap: 12,
                    gridTemplateColumns: "1fr 1fr",
                  }}
                >
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 8, color: "#555" }}>
                      Avant
                    </div>
                    <CodeBox text={fix.before} />
                  </div>
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 8, color: "#555" }}>
                      Après
                    </div>
                    <CodeBox text={fix.after} />
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        <div style={{ marginTop: 18, color: "#777", fontSize: 13 }}>
          (test)
        </div>
      </div>
    </div>
  );
}

export default Fixes;