import { useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { normalizeSeverity } from "../utils/severity";
import { COLORS, SHADOWS } from "../constants/styles";

const bg = COLORS.background;
const card = COLORS.card;
const shadow = SHADOWS.card;

// Retourne le style du badge selon la sévérité
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

// Calcule un score de sécurité basé sur les findings
function computeScore(findings) {
  let score = 100;
  for (const f of findings) {
    if (f.severity === "Critical") score -= 20;
    else if (f.severity === "High") score -= 12;
    else if (f.severity === "Medium") score -= 7;
    else if (f.severity === "Low") score -= 3;
    else score -= 1;
  }
  return Math.max(0, score);
}

// Formate un chemin de fichier avec numéro de ligne
function makeFileLine(file, line) {
  if (!file) return "—";
  if (line === null || line === undefined || line === "—") return String(file);
  return `${file}:${line}`;
}

// Extrait la meilleure description disponible
function bestDescription(obj) {
  return obj?.snippet || obj?.title || obj?.description || obj?.message || "Aucune description disponible.";
}

// Récupère les résultats Semgrep depuis différentes structures possibles
function getSemgrepResults(semgrepResult) {
  if (!semgrepResult) return [];

  const candidates = [
    semgrepResult?.results,
    semgrepResult?.issues,
    semgrepResult?.raw?.results,
    semgrepResult?.raw?.issues,
    semgrepResult?.data?.results,
    semgrepResult?.data?.issues,
    semgrepResult?.output?.results,
  ];

  for (const c of candidates) {
    if (Array.isArray(c)) return c;
  }
  return [];
}

// Transforme les issues Semgrep en format standardisé
function mapSemgrepIssues(issues) {
  return (issues || []).map((r, idx) => {
    const titleFull = r?.title || r?.check_id || r?.rule_id || "Finding";
    const MAX_TITLE = 38;
    const title = titleFull.length > MAX_TITLE ? titleFull.slice(0, MAX_TITLE - 1) + "…" : titleFull;

    const severity = normalizeSeverity(r?.severity);
    const owasp = r?.owasp_id || "—";

    const file = r?.path || r?.file || "—";
    const line = r?.start?.line ?? r?.line ?? "—";

    const fileFull = makeFileLine(file, line);
    const fileShort = fileFull.length > 72 ? "…" + fileFull.slice(fileFull.length - 72) : fileFull;

    return {
      id: `semgrep-${idx}-${fileFull}-${titleFull}`,
      title,
      titleFull,
      severity,
      owasp,
      file: fileShort,
      fileFull,
      lineNumber: line,
      description: bestDescription(r),
      source: "Semgrep",
    };
  });
}

// Transforme les findings TruffleHog en format standardisé
function mapTrufflehogFindings(trufflehogResult) {
  const list =
    trufflehogResult?.raw?.findings ||
    trufflehogResult?.raw?.results ||
    trufflehogResult?.findings ||
    trufflehogResult?.results ||
    [];

  if (!Array.isArray(list)) return [];

  return list.map((x, idx) => {
    const path =
      x?.path ||
      x?.file ||
      x?.filename ||
      x?.source?.file ||
      x?.source?.path ||
      x?.location?.path ||
      x?.location?.file ||
      "—";

    const line =
      x?.line ??
      x?.line_number ??
      x?.source?.line ??
      x?.source?.line_number ??
      x?.start_line ??
      x?.location?.line ??
      x?.location?.line_number ??
      x?.source?.start_line ??
      "—";

    const titleFull =
      x?.description ||
      x?.reason ||
      x?.detector_name ||
      x?.detector ||
      x?.type ||
      "Secret detected";

    const title = titleFull.length > 52 ? titleFull.slice(0, 51) + "…" : titleFull;

    const fileFull = line !== "—" ? `${path}:${line}` : path;
    const fileShort = fileFull.length > 72 ? "…" + fileFull.slice(fileFull.length - 72) : fileFull;

    const description = x?.raw || x?.details || x?.message || x?.reason || "Secret détecté par TruffleHog.";

    return {
      id: `trufflehog-${idx}-${fileFull}-${titleFull}`,
      title,
      titleFull,
      severity: "High",
      owasp: "A07:2025",
      file: fileShort,
      fileFull,
      lineNumber: line !== "—" ? line : "—",
      description,
      source: "TruffleHog",
    };
  });
}

// Transforme les findings Bandit en format standardisé
function mapBanditFindings(banditResult) {
  const list = banditResult?.issues || banditResult?.raw?.results || banditResult?.raw?.issues || [];
  if (!Array.isArray(list)) return [];

  return list.map((x, idx) => {
    const titleFull = x?.test_name || x?.issue_text || x?.title || "Bandit issue";
    const title = titleFull.length > 52 ? titleFull.slice(0, 51) + "…" : titleFull;

    const severityRaw = x?.issue_severity || x?.severity || "Medium";
    const severity = normalizeSeverity(severityRaw);

    const file = x?.filename || x?.file || "—";
    const line = x?.line_number ?? x?.line ?? "—";

    const fileFull = makeFileLine(file, line);
    const fileShort = fileFull.length > 72 ? "…" + fileFull.slice(fileFull.length - 72) : fileFull;

    return {
      id: `bandit-${idx}-${fileFull}-${titleFull}`,
      title,
      titleFull,
      severity,
      owasp: "—",
      file: fileShort,
      fileFull,
      lineNumber: line,
      description: x?.issue_text || x?.more_info || "Issue détectée par Bandit.",
      source: "Bandit",
    };
  });
}

// Affiche le dashboard avec tous les résultats d'analyse
export default function Dashboard() {
  const navigate = useNavigate();
  const location = useLocation();

  const [severityFilter, setSeverityFilter] = useState("All");
  const [sourceFilter, setSourceFilter] = useState("All");
  const [owaspFilter, setOwaspFilter] = useState("All");
  const [openId, setOpenId] = useState(null);

  const scanResults = location.state?.scanResults || null;

  const semgrepResult = scanResults?.semgrepResult || null;
  const banditResult = scanResults?.banditResult || null;
  const trufflehogResult = scanResults?.trufflehogResult || null;

  const semgrepFindings = useMemo(() => mapSemgrepIssues(getSemgrepResults(semgrepResult)), [semgrepResult]);
  const truffleFindings = useMemo(() => mapTrufflehogFindings(trufflehogResult), [trufflehogResult]);
  const banditFindings = useMemo(() => mapBanditFindings(banditResult), [banditResult]);

  const findings = useMemo(() => [...semgrepFindings, ...truffleFindings, ...banditFindings], [
    semgrepFindings,
    truffleFindings,
    banditFindings,
  ]);

  const availableSeverities = useMemo(() => {
    const set = new Set(findings.map((f) => f.severity));
    return ["All", ...Array.from(set)];
  }, [findings]);

  const availableOwasp = useMemo(() => {
    const set = new Set(findings.map((f) => f.owasp).filter((x) => x && x !== "—"));
    return ["All", ...Array.from(set)];
  }, [findings]);

  const availableSources = useMemo(() => {
    const set = new Set(findings.map((f) => f.source));
    return ["All", ...Array.from(set)];
  }, [findings]);

  const filtered = useMemo(() => {
    return findings.filter((f) => {
      if (severityFilter !== "All" && f.severity !== severityFilter) return false;
      if (sourceFilter !== "All" && f.source !== sourceFilter) return false;
      if (owaspFilter !== "All" && f.owasp !== owaspFilter) return false;
      return true;
    });
  }, [findings, severityFilter, sourceFilter, owaspFilter]);

  const score = useMemo(() => computeScore(findings), [findings]);

  const banditCount = banditResult?.error ? "—" : banditResult?.summary?.issues ?? 0;
  const truffleCount = trufflehogResult?.raw?.findings?.length ?? trufflehogResult?.summary?.secrets ?? 0;

  if (!scanResults) {
    return (
      <div style={{ minHeight: "100vh", background: bg, padding: 28 }}>
        <div style={{ maxWidth: 1100, margin: "0 auto" }}>
          <h1>Dashboard</h1>
          <p style={{ color: "#666" }}>Aucun résultat reçu. Lance une analyse depuis la page Upload.</p>
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
        {/* ✅ HEADER sans bouton */}
        <div style={{ display: "flex", alignItems: "center" }}>
          <h1 style={{ margin: 0 }}>Dashboard</h1>
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
            flexWrap: "wrap",
          }}
        >
          <div style={{ minWidth: 280 }}>
            <h2 style={{ marginTop: 0 }}>Score global</h2>
            <p style={{ margin: "6px 0", color: "#666" }}>
              {filtered.length} vulnérabilité(s) affichée(s) (sur {findings.length})
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

          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            <div
              style={{
                minWidth: 220,
                borderRadius: 20,
                background: "rgba(173, 216, 230, 0.22)",
                border: "1px solid rgba(100, 149, 237, 0.25)",
                padding: 16,
                color: "#1f4aa5",
              }}
            >
              <div style={{ fontWeight: 800, fontSize: 14 }}>Bandit</div>
              <div style={{ marginTop: 6, fontSize: 26, fontWeight: 800 }}>{banditCount}</div>
              <div style={{ marginTop: 4, fontSize: 12, color: "#2a4f9b" }}>
                {banditResult?.error ? "Non disponible" : "issue(s) détectée(s)"}
              </div>
            </div>

            <div
              style={{
                minWidth: 220,
                borderRadius: 20,
                background: "rgba(144, 238, 144, 0.18)",
                border: "1px solid rgba(60, 179, 113, 0.25)",
                padding: 16,
                color: "#1f7a3b",
              }}
            >
              <div style={{ fontWeight: 800, fontSize: 14 }}>TruffleHog</div>
              <div style={{ marginTop: 6, fontSize: 26, fontWeight: 800 }}>{truffleCount}</div>
              <div style={{ marginTop: 4, fontSize: 12, color: "#2b7f46" }}>
                {trufflehogResult?.error ? "Erreur TruffleHog" : "secret(s) détecté(s)"}
              </div>
            </div>
          </div>
        </div>

        {(banditResult?.error || trufflehogResult?.error) && (
          <div
            style={{
              marginTop: 14,
              background: "rgba(255, 205, 120, 0.22)",
              border: "1px solid rgba(255, 170, 60, 0.30)",
              borderRadius: 18,
              padding: 14,
              color: "#7a4a00",
            }}
          >
            <div style={{ fontWeight: 800 }}>Certain(s) outils n’ont pas pu s’exécuter</div>
            <ul style={{ margin: "8px 0 0 18px" }}>
              {banditResult?.error && <li>Bandit : {banditResult.error}</li>}
              {trufflehogResult?.error && <li>TruffleHog : {trufflehogResult.error}</li>}
            </ul>
          </div>
        )}

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
                style={{ padding: "10px 12px", borderRadius: 12, border: "1px solid #ddd", background: "#fff" }}
              >
                {availableSeverities.map((s) => (
                  <option key={s} value={s}>
                    {s === "All" ? "Toutes les sévérités" : s}
                  </option>
                ))}
              </select>

              <select
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                style={{ padding: "10px 12px", borderRadius: 12, border: "1px solid #ddd", background: "#fff" }}
              >
                {availableSources.map((src) => (
                  <option key={src} value={src}>
                    {src === "All" ? "Toutes les sources" : src}
                  </option>
                ))}
              </select>

              <select
                value={owaspFilter}
                onChange={(e) => setOwaspFilter(e.target.value)}
                style={{ padding: "10px 12px", borderRadius: 12, border: "1px solid #ddd", background: "#fff" }}
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
                  setSourceFilter("All");
                  setOwaspFilter("All");
                  setOpenId(null);
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
                  <th style={{ padding: "14px 10px", borderBottom: "1px solid #eee" }}>Ligne</th>
                </tr>
              </thead>

              <tbody>
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={5} style={{ padding: 16, color: "#777" }}>
                      Aucune vulnérabilité à afficher.
                    </td>
                  </tr>
                ) : (
                  filtered.map((f) => {
                    const isOpen = openId === f.id;

                    return (
                      <>
                        <tr
                          key={f.id}
                          onClick={() => setOpenId(isOpen ? null : f.id)}
                          style={{ cursor: "pointer" }}
                        >
                          <td style={{ padding: "14px 10px", borderBottom: "1px solid #f0f0f0" }}>
                            <span
                              style={{ display: "inline-flex", alignItems: "center", gap: 10, fontWeight: 650 }}
                              title={f.titleFull}
                            >
                              <span
                                aria-hidden
                                style={{
                                  width: 18,
                                  display: "inline-block",
                                  transform: isOpen ? "rotate(90deg)" : "rotate(0deg)",
                                  transition: "transform 120ms ease",
                                  color: "#333",
                                  fontSize: 18,
                                  lineHeight: "18px",
                                }}
                              >
                                ›
                              </span>
                              {f.title}
                            </span>
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
                            <span
                              title={f.fileFull}
                              style={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 12 }}
                            >
                              {f.file}
                            </span>
                          </td>

                          <td style={{ padding: "14px 10px", borderBottom: "1px solid #f0f0f0", color: "#555" }}>
                            {f.lineNumber ?? "—"}
                          </td>
                        </tr>

                        {isOpen && (
                          <tr key={`${f.id}-details`}>
                            <td colSpan={5} style={{ padding: 0, borderBottom: "1px solid #f0f0f0" }}>
                              <div
                                style={{
                                  display: "grid",
                                  gridTemplateColumns: "1.7fr 0.9fr",
                                  gap: 16,
                                  padding: 16,
                                  background: "#f1f1f1",
                                }}
                              >
                                <div style={{ background: "#e9e9e9", borderRadius: 12, padding: 14 }}>
                                  <div style={{ fontWeight: 800, marginBottom: 8 }}>Description détaillée :</div>
                                  <div style={{ color: "#444", whiteSpace: "pre-wrap" }}>{f.description}</div>
                                </div>

                                <div style={{ background: "#e9e9e9", borderRadius: 12, padding: 14 }}>
                                  <div style={{ fontWeight: 800, marginBottom: 8 }}>Outil source :</div>
                                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                                    <span style={{ fontSize: 18 }}>✓</span>
                                    <span style={{ fontWeight: 800 }}>{f.source}</span>
                                  </div>
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* ✅ BOUTON "Voir corrections" en bas centré */}
        <div style={{ display: "flex", justifyContent: "center", marginTop: 30 }}>
          <button
            onClick={() => navigate("/fixes", { state: { semgrepResult, scanResults } })}
            style={{
              backgroundColor: "rgba(255, 182, 193, 0.25)",
              color: "#c04c78",
              border: "1px solid rgba(255, 182, 193, 0.6)",
              padding: "14px 28px",
              borderRadius: 18,
              cursor: "pointer",
              fontWeight: 700,
              fontSize: 15,
              boxShadow: "0 6px 18px rgba(0,0,0,0.05)",
            }}
          >
            Voir corrections
          </button>
        </div>
      </div>
    </div>
  );
}