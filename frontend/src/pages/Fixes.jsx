import { useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

// Composant badge affichant la sévérité
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
    Info: {
      bg: "rgba(200,200,200,0.18)",
      border: "rgba(180,180,180,0.6)",
      text: "#555",
    },
  };

  const s = styles[severity] ?? styles.Info;

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
        fontWeight: 700,
        whiteSpace: "nowrap",
      }}
    >
      {severity}
    </span>
  );
}

// Composant badge affichant le code OWASP
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
        fontWeight: 700,
        color: "#444",
        whiteSpace: "nowrap",
      }}
    >
      {code}
    </span>
  );
}

// Composant affichant du code formaté
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
        whiteSpace: "pre-wrap",
      }}
    >
      {text}
    </pre>
  );
}

// Normalise la sévérité brute en niveau standardisé
function normalizeSeverity(raw) {
  const s = String(raw || "medium").toLowerCase();
  if (s.includes("critical")) return "Critical";
  if (s.includes("high") || s === "error") return "High";
  if (s.includes("low")) return "Low";
  if (s.includes("medium") || s === "warning" || s.includes("warn")) return "Medium";
  return "Info";
}

// Extrait le code OWASP depuis les métadonnées Semgrep
function pickOwasp(item) {
  const md = item?.extra?.metadata || {};
  const candidates = [md?.owasp, md?.owasp_top_10, md?.category, md?.cwe];

  let val = candidates.find(Boolean);
  if (Array.isArray(val)) val = val[0];
  if (!val) return "—";

  const s = String(val);
  const match = s.match(/A\d{2}/);
  if (match) return match[0];
  return s;
}

// Raccourcit un chemin de fichier trop long
function shortPath(p) {
  if (!p) return "—";
  const max = 80;
  if (p.length <= max) return p;
  return "…" + p.slice(p.length - max);
}

// Construit la liste des corrections à partir du résultat Semgrep
function buildFixesFromSemgrep(semgrepResult) {
  const results = semgrepResult?.raw?.results || [];
  if (!Array.isArray(results)) return [];

  return results.map((r, idx) => {
    const title = r?.check_id || r?.extra?.message || "Issue détectée";

    const path = r?.path || r?.extra?.path || "unknown";
    const start = r?.start?.line || r?.extra?.start?.line;
    const end = r?.end?.line || r?.extra?.end?.line;

    const severityRaw = r?.extra?.severity || r?.severity;
    const severity = normalizeSeverity(severityRaw);
    const owasp = pickOwasp(r);

    const before =
      r?.extra?.lines ||
      r?.lines ||
      r?.extra?.code ||
      "(code indisponible)";

    const after =
      r?.extra?.fix ||
      r?.fix ||
      r?.extra?.autofix ||
      "(pas de fix automatique — à corriger manuellement)";

    return {
      id: `fix-${idx}`,
      title,
      fileFull: start ? `${path}:${start}${end ? `-${end}` : ""}` : path,
      fileDisplay: shortPath(start ? `${path}:${start}${end ? `-${end}` : ""}` : path),
      owasp,
      severity,
      before,
      after,
    };
  });
}

// Page principale affichant les corrections et le rapport
export default function Fixes() {
  const { state } = useLocation();
  const navigate = useNavigate();
  const semgrepResult = state?.semgrepResult;

  // On garde scanResults si on l'a (utile pour revenir proprement au dashboard)
  const scanResults = state?.scanResults;

  const fixes = useMemo(() => buildFixesFromSemgrep(semgrepResult), [semgrepResult]);

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
    lines.push("SecureScan - Rapport");
    lines.push(`Date: ${new Date().toLocaleString()}`);
    lines.push("");
    lines.push("Corrections sélectionnées:");

    fixes
      .filter((f) => selected.has(f.id))
      .forEach((f) =>
        lines.push(`- ${f.title} | ${f.fileFull} | ${f.owasp} | ${f.severity}`)
      );

    if (selectedCount === 0) lines.push("- (Aucune)");

    const blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = "securescan_report.txt";
    a.click();

    URL.revokeObjectURL(url);
  };

  if (!semgrepResult) {
    return (
      <div style={{ maxWidth: 900, margin: "60px auto", padding: 20 }}>
        <h2>Corrections</h2>
        <p style={{ color: "#666" }}>
          Aucun résultat d’analyse trouvé. Reviens au dashboard.
        </p>
        <button
          onClick={() => navigate("/dashboard")}
          style={{
            backgroundColor: "rgba(255, 182, 193, 0.25)",
            color: "#c04c78",
            border: "1px solid rgba(255, 182, 193, 0.6)",
            padding: "10px 14px",
            borderRadius: 14,
            cursor: "pointer",
            fontWeight: 700,
          }}
        >
          Retour dashboard
        </button>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 1100, margin: "40px auto", padding: "0 20px" }}>
      {/* HEADER */}
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
              fontWeight: 700,
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
              fontWeight: 700,
            }}
          >
            Télécharger rapport
          </button>

          <button
            onClick={() => {
              // Retour "propre": si scanResults existe on le renvoie, sinon on garde l'ancien fallback
              if (scanResults) navigate("/dashboard", { state: { scanResults } });
              else navigate("/dashboard", { state: { semgrepResult } });
            }}
            style={{
              backgroundColor: "rgba(0,0,0,0.05)",
              color: "#444",
              border: "1px solid #ddd",
              padding: "10px 14px",
              borderRadius: 14,
              cursor: "pointer",
              fontWeight: 700,
            }}
          >
            Retour dashboard
          </button>
        </div>
      </div>

      {/* STATUS */}
      {status === "done" && (
        <div
          style={{
            marginTop: 14,
            padding: 14,
            backgroundColor: "white",
            borderRadius: 18,
            boxShadow: "0 8px 30px rgba(0,0,0,0.05)",
            border: "1px solid #f1f1f1",
            display: "flex",
            gap: 10,
            alignItems: "center",
          }}
        >
          Corrections appliquées (demo).
        </div>
      )}

      {/* LIST */}
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

        {fixes.length === 0 ? (
          <div style={{ marginTop: 16, color: "#666" }}>
            Aucun finding Semgrep trouvé dans le résultat.
          </div>
        ) : (
          <div style={{ marginTop: 18, display: "grid", gap: 16 }}>
            {fixes.map((fix) => {
              const checked = selected.has(fix.id);

              return (
                <div
                  key={fix.id}
                  style={{
                    border: checked
                      ? "1px solid rgba(255, 182, 193, 0.55)"
                      : "1px solid #eee",
                    borderRadius: 18,
                    padding: 18,
                    backgroundColor: checked
                      ? "rgba(255, 182, 193, 0.06)"
                      : "white",
                    boxShadow: checked ? "0 10px 30px rgba(0,0,0,0.04)" : "none",
                  }}
                >
                  {/* HEADER */}
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      gap: 14,
                      flexWrap: "wrap",
                      alignItems: "flex-start",
                    }}
                  >
                    <label
                      style={{
                        display: "flex",
                        gap: 12,
                        alignItems: "flex-start",
                        cursor: "pointer",
                        flex: "1 1 520px",
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => toggle(fix.id)}
                        style={{ marginTop: 4 }}
                      />

                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontWeight: 800, fontSize: 15, lineHeight: 1.25 }}>
                          {fix.title}
                        </div>

                        <div style={{ marginTop: 8, color: "#666", fontSize: 13 }}>
                          <span style={{ color: "#777" }}>Fichier :</span>{" "}
                          <b
                            title={fix.fileFull}
                            style={{
                              fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
                              fontWeight: 700,
                            }}
                          >
                            {fix.fileDisplay}
                          </b>
                        </div>
                      </div>
                    </label>

                    <div
                      style={{
                        display: "flex",
                        gap: 8,
                        alignItems: "center",
                        flexWrap: "wrap",
                        justifyContent: "flex-end",
                      }}
                    >
                      <OwaspBadge code={fix.owasp} />
                      <SeverityBadge severity={fix.severity} />
                    </div>
                  </div>

                  {/* BEFORE / AFTER */}
                  <div
                    style={{
                      marginTop: 16,
                      display: "grid",
                      gap: 12,
                      gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
                    }}
                  >
                    <div>
                      <div style={{ fontSize: 12, fontWeight: 800, marginBottom: 8, color: "#555" }}>
                        Avant
                      </div>
                      <CodeBox text={fix.before} />
                    </div>

                    <div>
                      <div style={{ fontSize: 12, fontWeight: 800, marginBottom: 8, color: "#555" }}>
                        Après
                      </div>
                      <CodeBox text={fix.after} />
                    </div>
                  </div>

                  {/* FOOTER */}
                  <div style={{ marginTop: 12, color: "#888", fontSize: 12 }}>
                    {fix.after && fix.after.startsWith("(")
                      ? "Suggestion: corriger manuellement / créer une PR."
                      : ""}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        <div style={{ marginTop: 18, color: "#777", fontSize: 13 }}>
          Note: “Appliquer” est en mode demo (pas de commit automatique).
        </div>
      </div>
    </div>
  );
}