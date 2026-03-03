import { useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

const bg = "#f3f3f3";
const card = "#ffffff";
const shadow = "0 12px 40px rgba(0,0,0,0.06)";

// Transforme la sévérité brute reçue de Semgrep en un niveau standardisé
function normalizeSeverity(s) {
  const v = (s || "").toString().toLowerCase();

  if (v.includes("critical")) return "Critical";
  if (v.includes("high") || v === "error") return "High";
  if (v.includes("medium") || v === "warning" || v.includes("warn")) return "Medium";
  if (v.includes("low")) return "Low";

  return "Info";
}

// Retourne le style visuel du badge selon le niveau de sévérité
function badgeStyleForSeverity(sev) {
  switch (sev) {
    case "Critical":
      return {
        backgroundColor: "rgba(255, 182, 193, 0.28)",
        border: "1px solid rgba(255, 105, 180, 0.35)",
        color: "#b23a68",
      };
    case "High":
      return {
        backgroundColor: "rgba(255, 205, 120, 0.30)",
        border: "1px solid rgba(255, 170, 60, 0.40)",
        color: "#9a5a00",
      };
    case "Medium":
      return {
        backgroundColor: "rgba(173, 216, 230, 0.35)",
        border: "1px solid rgba(100, 149, 237, 0.35)",
        color: "#1f4aa5",
      };
    case "Low":
      return {
        backgroundColor: "rgba(144, 238, 144, 0.28)",
        border: "1px solid rgba(60, 179, 113, 0.35)",
        color: "#1f7a3b",
      };
    default:
      return {
        backgroundColor: "rgba(210, 210, 210, 0.35)",
        border: "1px solid rgba(180, 180, 180, 0.55)",
        color: "#555",
      };
  }
}

function extractOwaspFromResult(r) {
  const md = r?.extra?.metadata || {};

  // ⚠️ OWASP only (pas de cwe, pas de category)
  const candidates = [md?.owasp, md?.owasp_top_10];

  let val = candidates.find(Boolean);

  if (Array.isArray(val)) val = val[0];
  if (!val) return "—";

  const s = String(val);

  // Exemple: "A01:2021 - Broken Access Control" => "A01"
  const match = s.match(/A\d{2}/);
  if (match) return match[0];

  return s;
}

// Calcule un score de sécurité global sur 100 en retirant des points selon la gravité des vulnérabilités
function computeScore(findings) {
  let score = 100;
  for (const f of findings) {
    const sev = f.severity;
    if (sev === "Critical") score -= 20;
    else if (sev === "High") score -= 12;
    else if (sev === "Medium") score -= 7;
    else if (sev === "Low") score -= 3;
    else score -= 1;
  }
  if (score < 0) score = 0;
  return score;
}

// Composant React qui affiche le tableau de bord des vulnerabilités détectées
export default function Dashboard() {
  const navigate = useNavigate();
  const location = useLocation();

  const [severityFilter, setSeverityFilter] = useState("All");
  const [owaspFilter, setOwaspFilter] = useState("All");

  const semgrepResult = location.state?.semgrepResult || null;
  const rawResults = semgrepResult?.raw?.results || [];

  const findings = useMemo(() => {
    return rawResults.map((r) => {
      const title = r?.check_id || r?.extra?.message || "Semgrep finding";
      const severity = normalizeSeverity(r?.extra?.severity || r?.severity);
      const owasp = extractOwaspFromResult(r);
      const filePath = r?.path || r?.extra?.path || "—";

      return {
        id: `${title}-${filePath}-${r?.start?.line || ""}`,
        title,
        severity,
        owasp,
        file: filePath,
      };
    });
  }, [rawResults]);

  const availableSeverities = useMemo(() => {
    const set = new Set(findings.map((f) => f.severity));
    return ["All", ...Array.from(set)];
  }, [findings]);

  const availableOwasp = useMemo(() => {
    const set = new Set(findings.map((f) => f.owasp).filter(Boolean));
    return ["All", ...Array.from(set)];
  }, [findings]);

  const filtered = useMemo(() => {
    return findings.filter((f) => {
      if (severityFilter !== "All" && f.severity !== severityFilter) return false;
      if (owaspFilter !== "All" && f.owasp !== owaspFilter) return false;
      return true;
    });
  }, [findings, severityFilter, owaspFilter]);

  const score = useMemo(() => computeScore(findings), [findings]);

  if (!semgrepResult) {
    return (
      <div style={{ minHeight: "100vh", background: bg, padding: 28 }}>
        <div style={{ maxWidth: 1100, margin: "0 auto" }}>
          <h1>Dashboard</h1>
          <p style={{ color: "#666" }}>
            Aucun résultat reçu. Lance une analyse depuis la page Upload.
          </p>
          <button
            onClick={() => navigate("/")}
            style={{
              backgroundColor: "rgba(255, 182, 193, 0.25)",
              color: "#c04c78",
              border: "1px solid rgba(255, 182, 193, 0.6)",
              padding: "10px 16px",
              borderRadius: 14,
              cursor: "pointer",
              fontWeight: 600,
            }}
          >
            Retour à l’upload
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ minHeight: "100vh", background: bg, padding: 28 }}>
      <div style={{ maxWidth: 1200, margin: "0 auto" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h1 style={{ margin: 0 }}>Dashboard</h1>

          <button
            onClick={() => navigate("/fixes", { state: { semgrepResult } })}
            style={{
              backgroundColor: "rgba(255, 182, 193, 0.25)",
              color: "#c04c78",
              border: "1px solid rgba(255, 182, 193, 0.6)",
              padding: "10px 16px",
              borderRadius: 14,
              cursor: "pointer",
              fontWeight: 600,
            }}
          >
            Voir corrections
          </button>
        </div>

        <div
          style={{
            marginTop: 18,
            background: card,
            borderRadius: 26,
            padding: 26,
            boxShadow: shadow,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            gap: 20,
          }}
        >
          <div>
            <h2 style={{ marginTop: 0 }}>Score global</h2>
            <p style={{ margin: "6px 0", color: "#666" }}>
              {filtered.length} vulnérabilité(s) affichée(s) (sur {findings.length})
            </p>
            <p style={{ margin: "6px 0", color: "#888", fontSize: 13 }}>
              Version Semgrep : {semgrepResult?.summary?.version ?? "n/a"}
            </p>
          </div>

          <div
            style={{
              minWidth: 240,
              textAlign: "center",
              borderRadius: 20,
              background: "rgba(255, 182, 193, 0.18)",
              border: "1px solid rgba(255, 182, 193, 0.5)",
              padding: 18,
              color: "#b54a72",
            }}
          >
            <div style={{ fontSize: 52, fontWeight: 800 }}>{score}/100</div>
          </div>
        </div>

        <div
          style={{
            marginTop: 22,
            background: card,
            borderRadius: 26,
            padding: 26,
            boxShadow: shadow,
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              gap: 14,
              flexWrap: "wrap",
            }}
          >
            <h2 style={{ margin: 0 }}>Vulnérabilités détectées</h2>

            <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                style={{
                  padding: "10px 12px",
                  borderRadius: 12,
                  border: "1px solid #ddd",
                  background: "#fff",
                }}
              >
                {availableSeverities.map((s) => (
                  <option key={s} value={s}>
                    {s === "All" ? "Toutes les sévérités" : s}
                  </option>
                ))}
              </select>

              <select
                value={owaspFilter}
                onChange={(e) => setOwaspFilter(e.target.value)}
                style={{
                  padding: "10px 12px",
                  borderRadius: 12,
                  border: "1px solid #ddd",
                  background: "#fff",
                }}
              >
                {availableOwasp.map((o) => (
                  <option key={o} value={o}>
                    {o === "All" ? "Toutes les catégories OWASP" : o}
                  </option>
                ))}
              </select>

              <button
                onClick={() => {
                  setSeverityFilter("All");
                  setOwaspFilter("All");
                }}
                style={{
                  backgroundColor: "rgba(255, 182, 193, 0.18)",
                  color: "#c04c78",
                  border: "1px solid rgba(255, 182, 193, 0.55)",
                  padding: "10px 14px",
                  borderRadius: 14,
                  cursor: "pointer",
                  fontWeight: 600,
                }}
              >
                Réinitialiser
              </button>
            </div>
          </div>

          <div style={{ marginTop: 18, overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ textAlign: "left", color: "#666" }}>
                  <th style={{ padding: "14px 10px", borderBottom: "1px solid #eee" }}>Titre</th>
                  <th style={{ padding: "14px 10px", borderBottom: "1px solid #eee" }}>Sévérité</th>
                  <th style={{ padding: "14px 10px", borderBottom: "1px solid #eee" }}>OWASP</th>
                  <th style={{ padding: "14px 10px", borderBottom: "1px solid #eee" }}>Fichier</th>
                </tr>
              </thead>

              <tbody>
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={4} style={{ padding: 16, color: "#777" }}>
                      Aucune vulnérabilité à afficher (ou aucun résultat Semgrep).
                    </td>
                  </tr>
                ) : (
                  filtered.map((f) => (
                    <tr key={f.id}>
                      <td style={{ padding: "14px 10px", borderBottom: "1px solid #f0f0f0" }}>
                        {f.title}
                      </td>
                      <td style={{ padding: "14px 10px", borderBottom: "1px solid #f0f0f0" }}>
                        <span
                          style={{
                            display: "inline-block",
                            padding: "6px 10px",
                            borderRadius: 999,
                            fontWeight: 700,
                            fontSize: 13,
                            ...badgeStyleForSeverity(f.severity),
                          }}
                        >
                          {f.severity}
                        </span>
                      </td>
                      <td style={{ padding: "14px 10px", borderBottom: "1px solid #f0f0f0", color: "#555" }}>
                        {f.owasp}
                      </td>
                      <td style={{ padding: "14px 10px", borderBottom: "1px solid #f0f0f0", color: "#555" }}>
                        {f.file}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {import.meta.env.DEV && (
            <details style={{ marginTop: 16 }}>
              <summary style={{ cursor: "pointer", color: "#666" }}>
                Debug : afficher le JSON brut Semgrep
              </summary>
              <pre style={{ whiteSpace: "pre-wrap", fontSize: 12, marginTop: 10 }}>
                {JSON.stringify(semgrepResult.raw, null, 2)}
              </pre>
            </details>
          )}
        </div>
      </div>
    </div>
  );
}