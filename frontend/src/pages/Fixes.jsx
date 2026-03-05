import { useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { autoFixGithub, getScanDetails, listScans } from "../api/scans";
import SeverityBadge from "../components/SeverityBadge";
import OwaspBadge from "../components/OwaspBadge";
import CodeBox from "../components/CodeBox";
import { normalizeSeverity } from "../utils/severity";
import { pickOwasp } from "../utils/owasp";
import { shortPath } from "../utils/paths";
import { formatDate, downloadTextFile } from "../utils/reports";

// Construit la liste des corrections depuis les résultats Semgrep
function buildFixesFromSemgrep(semgrepResult, findingIdMap, allFindings = []) {
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

    const normalizedPath = path.replace(/^.*\/(repo|project)\//, "").replace(/\\/g, "/");
    const fileName = path.split("/").pop();
    const key1 = `${r?.check_id || ""}|${path}|${start || ""}`;
    const key2 = `${r?.check_id || ""}|${normalizedPath}|${start || ""}`;
    const key3 = `${r?.check_id || ""}|${fileName}|${start || ""}`;
    let findingId = findingIdMap?.[key1] || findingIdMap?.[key2] || findingIdMap?.[key3];
    
    if (!findingId && allFindings.length > 0) {
      const matchingFinding = allFindings.find(
        (f) =>
          (f.file_path === path || f.file_path === normalizedPath || f.file_path?.endsWith(fileName)) &&
          (f.line_start === start || f.line_start === parseInt(start))
      );
      if (matchingFinding) {
        findingId = matchingFinding.id;
      } else if (allFindings.length === 1) {
        findingId = allFindings[0].id;
      } else if (idx < allFindings.length) {
        findingId = allFindings[idx].id;
      }
    }

    return {
      id: `semgrep-fix-${idx}`,
      title,
      fileFull: start ? `${path}:${start}${end ? `-${end}` : ""}` : path,
      fileDisplay: shortPath(start ? `${path}:${start}${end ? `-${end}` : ""}` : path),
      owasp,
      severity,
      before,
      after,
      findingId,
    };
  });
}

// Construit la liste des corrections depuis les résultats Bandit
function buildFixesFromBandit(banditResult, findingIdMap, allFindings = []) {
  const results = banditResult?.raw?.results || banditResult?.issues || [];
  if (!Array.isArray(results)) return [];

  return results.map((r, idx) => {
    const title = r?.test_id || r?.issue_text || r?.title || "Issue détectée";
    const path = r?.filename || r?.file || "unknown";
    const start = r?.line_number || r?.line || null;
    
    const severityRaw = r?.issue_severity || r?.severity;
    const severity = normalizeSeverity(severityRaw);
    const owasp = r?.owasp_id || "—";

    const before = r?.code || r?.snippet || "(code indisponible)";
    
    // Génère une suggestion de correction basée sur le type de vulnérabilité
    let after = "(pas de fix automatique — à corriger manuellement)";
    if (title.includes("yaml.load") || r?.test_id === "B506") {
      after = "yaml.load(yaml_text, Loader=yaml.Loader)";
    } else if (title.includes("pickle.load") || r?.test_id === "B301") {
      after = "pickle.load(file)  # WARNING: Only load trusted data";
    } else if (title.includes("eval") || r?.test_id === "B307") {
      after = "ast.literal_eval(...)  # Use ast.literal_eval instead of eval";
    } else if (title.includes("shell=True") || r?.test_id === "B602") {
      after = "subprocess.run(..., shell=False)";
    }

    const normalizedPath = path.replace(/^.*\/(repo|project)\//, "").replace(/\\/g, "/");
    const fileName = path.split("/").pop();
    const ruleId = r?.test_id || r?.rule_id || "";
    const key1 = `${ruleId}|${path}|${start || ""}`;
    const key2 = `${ruleId}|${normalizedPath}|${start || ""}`;
    const key3 = `${ruleId}|${fileName}|${start || ""}`;
    let findingId = findingIdMap?.[key1] || findingIdMap?.[key2] || findingIdMap?.[key3];
    
    if (!findingId && allFindings.length > 0) {
      const matchingFinding = allFindings.find(
        (f) =>
          (f.file_path === path || f.file_path === normalizedPath || f.file_path?.endsWith(fileName)) &&
          (f.line_start === start || f.line_start === parseInt(start))
      );
      if (matchingFinding) {
        findingId = matchingFinding.id;
      } else if (idx < allFindings.length) {
        findingId = allFindings[idx].id;
      }
    }

    return {
      id: `bandit-fix-${idx}`,
      title,
      fileFull: start ? `${path}:${start}` : path,
      fileDisplay: shortPath(start ? `${path}:${start}` : path),
      owasp,
      severity,
      before,
      after,
      findingId,
    };
  });
}

// Page de gestion des corrections et génération de rapports
export default function Fixes() {
  const { state } = useLocation();
  const navigate = useNavigate();
  const semgrepResult = state?.semgrepResult;
  const banditResult = state?.scanResults?.banditResult || state?.banditResult;

  // On garde scanResults si on l'a (utile pour revenir proprement au dashboard)
  const scanResults = state?.scanResults;

  const [findingIdMap, setFindingIdMap] = useState({});
  const [allFindings, setAllFindings] = useState([]);

  const fixes = useMemo(() => {
    const semgrepFixes = buildFixesFromSemgrep(semgrepResult, findingIdMap, allFindings);
    const banditFixes = buildFixesFromBandit(banditResult, findingIdMap, allFindings);
    
    // Combine les deux listes
    const allFixes = [...semgrepFixes, ...banditFixes];
    
    // Déduplique les fixes qui pointent vers le même fichier/ligne
    // Si deux fixes ont le même fichier et la même ligne, on garde seulement le premier
    const seen = new Map(); // Map<fileFull, fix>
    
    for (const fix of allFixes) {
      // Extrait le fichier et la ligne depuis fileFull (format: "path/to/file.py:33")
      const fileLineMatch = fix.fileFull.match(/^(.+):(\d+)/);
      if (fileLineMatch) {
        const filePath = fileLineMatch[1];
        const lineNum = fileLineMatch[2];
        const key = `${filePath}:${lineNum}`;
        
        // Si on a déjà une vulnérabilité sur cette ligne, on garde la première
        if (!seen.has(key)) {
          seen.set(key, fix);
        }
      } else {
        // Si pas de numéro de ligne, utilise le fichier complet comme clé
        const key = fix.fileFull;
        if (!seen.has(key)) {
          seen.set(key, fix);
        }
      }
    }
    
    return Array.from(seen.values());
  }, [semgrepResult, banditResult, findingIdMap, allFindings]);

  const [selected, setSelected] = useState(() => new Set());
  const [status, setStatus] = useState("idle"); // idle | applying | done | applied | error
  const [autoFixRepoUrl, setAutoFixRepoUrl] = useState(
    scanResults?.semgrepResult?.input?.repo_url || scanResults?.input?.repo_url || ""
  );
  const [autoFixToken, setAutoFixToken] = useState("");
  const [autoFixFindingId, setAutoFixFindingId] = useState("");
  const [autoFixMessage, setAutoFixMessage] = useState("");
  const [createdPRs, setCreatedPRs] = useState([]);
  const [lastAutoFixResult, setLastAutoFixResult] = useState(null);

  // Récupère les IDs de findings en base pour le scan courant (via /scans/{scan_id})
  useEffect(() => {
    const scanId =
      semgrepResult?.scan_id ||
      banditResult?.scan_id ||
      scanResults?.scan_ids?.semgrep ||
      scanResults?.scan_ids?.bandit ||
      scanResults?.scan_id ||
      null;

    (async () => {
      try {
        let targetScanId = scanId;

        // Si pas de scan_id direct, on récupère le dernier scan Semgrep ou Bandit
        if (!targetScanId) {
          const scans = await listScans(5);
          const semgrepScan = scans.find(
            (s) => s.source_type === "git" && s.semgrep_version && s.summary_json?.findings > 0
          );
          const banditScan = scans.find(
            (s) => s.source_type === "git" && s.summary_json?.issues > 0
          );
          if (semgrepScan) {
            targetScanId = semgrepScan.id;
          } else if (banditScan) {
            targetScanId = banditScan.id;
          }
        }

        if (!targetScanId) return;

        const details = await getScanDetails(targetScanId);
        const map = {};
        const findings = details.findings || [];
        
        findings.forEach((f) => {
          const meta = f.metadata_json || {};
          const rule = meta.rule_id || f.rule_id || "";
          const file = meta.file || f.file_path || "";
          const line = meta.line || f.line_start || "";
          
          // Plusieurs clés possibles pour améliorer la correspondance
          const normalizedFile = file.replace(/^.*\/(repo|project)\//, "").replace(/\\/g, "/");
          const key1 = `${rule}|${file}|${line}`;
          const key2 = `${rule}|${normalizedFile}|${line}`;
          const key3 = `${rule}|${file.split("/").pop()}|${line}`;
          
          map[key1] = f.id;
          map[key2] = f.id;
          map[key3] = f.id;
          
          // Aussi stocker par index pour fallback
          map[`index_${findings.indexOf(f)}`] = f.id;
        });
        setFindingIdMap(map);
        setAllFindings(findings); // Stocke aussi tous les findings pour fallback
      } catch {
        // en cas d'erreur, on laisse la map vide
      }
    })();
  }, [semgrepResult, scanResults]);

  const toggle = (id) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

    // Si on sélectionne une ligne qui possède déjà un findingId,
    // on le propose automatiquement dans le champ d'auto-fix.
    const fix = fixes.find((f) => f.id === id);
    if (fix?.findingId && !autoFixFindingId) {
      setAutoFixFindingId(fix.findingId);
    }
  };

  const selectedCount = selected.size;
  const canApply = selectedCount > 0 && status !== "applying";
  
  // Vérifie si on peut faire une vraie correction GitHub
  const selectedFixesWithId = fixes.filter((f) => selected.has(f.id) && f.findingId);
  const canDoRealFix = autoFixRepoUrl && autoFixToken && selectedFixesWithId.length > 0;

  const handleApply = async () => {
    if (!canApply) return;

    const selectedFixes = fixes.filter((f) => selected.has(f.id) && f.findingId);

    // Si on n'a pas les infos GitHub nécessaires, on reste en mode démo
    if (!autoFixRepoUrl || !autoFixToken || selectedFixes.length === 0) {
      setStatus("applying");
      setTimeout(() => setStatus("done"), 900);
      return;
    }

    try {
      setStatus("applying");
      setCreatedPRs([]);
      const prResults = [];

      // On applique un auto-fix GitHub pour chaque vulnérabilité sélectionnée
      for (const fix of selectedFixes) {
        try {
          const res = await autoFixGithub({
            repo_url: autoFixRepoUrl.trim(),
            github_token: autoFixToken.trim(),
            finding_id: fix.findingId,
            base_branch: "main",
            title: `SecureScan: fix ${fix.title}`,
          });
          const prUrl = res?.pr?.url || res?.pr?.html_url;
          const prNumber = res?.pr?.number;
          if (prUrl) {
            prResults.push({
              url: prUrl,
              number: prNumber,
              title: fix.title,
              file: fix.fileDisplay,
            });
          }
        } catch (err) {
          console.error(`Erreur pour ${fix.title}:`, err);
          prResults.push({
            error: true,
            title: fix.title,
            message: err.message,
          });
        }
      }

      setCreatedPRs(prResults);
      setStatus(prResults.length > 0 && prResults.some((p) => !p.error) ? "applied" : "error");
      if (prResults.length > 0 && prResults.some((p) => !p.error)) {
        const successCount = prResults.filter((p) => !p.error).length;
        setAutoFixMessage(
          `${successCount} Pull Request${successCount > 1 ? "s" : ""} créée${successCount > 1 ? "s" : ""} avec succès.`
        );
      } else {
        setAutoFixMessage("Erreur lors de l'application des corrections.");
      }
    } catch (e) {
      setStatus("error");
      setAutoFixMessage(`Erreur lors de l'application des corrections : ${e.message}`);
      setCreatedPRs([]);
    }
  };

  const generateAutoFixReport = (prResult, findingId) => {
    const lines = [];
    const date = new Date();
    const dateStr = formatDate(date);

    // Trouve le finding correspondant
    const finding = allFindings.find((f) => f.id === findingId);
    const fix = fixes.find((f) => f.findingId === findingId);

    // En-tête
    lines.push("=".repeat(80));
    lines.push("SECURESCAN - RAPPORT D'AUTO-FIX GITHUB");
    lines.push("=".repeat(80));
    lines.push("");
    lines.push(`Date de correction : ${dateStr}`);
    lines.push(`Repository : ${autoFixRepoUrl}`);
    lines.push("");

    // Pull Request créée
    lines.push("-".repeat(80));
    lines.push("PULL REQUEST CRÉÉE");
    lines.push("-".repeat(80));
    lines.push("");
    if (prResult?.pr) {
      lines.push(`Numéro de PR : #${prResult.pr.number || "N/A"}`);
      lines.push(`Titre : ${prResult.pr.title || "SecureScan: apply automated fix"}`);
      lines.push(`URL : ${prResult.pr.url || prResult.pr.html_url || "N/A"}`);
      lines.push(`État : ${prResult.pr.state || "open"}`);
      lines.push(`Branche : ${prResult.branch || "N/A"}`);
    } else {
      lines.push("Pull Request créée avec succès.");
      if (prResult.branch) lines.push(`Branche créée : ${prResult.branch}`);
    }
    lines.push("");

    // Détails de la vulnérabilité corrigée
    if (finding || fix) {
      lines.push("-".repeat(80));
      lines.push("VULNÉRABILITÉ CORRIGÉE");
      lines.push("-".repeat(80));
      lines.push("");
      if (finding) {
        lines.push(`ID de la vulnérabilité : ${finding.id}`);
        lines.push(`Outil : ${finding.tool || "N/A"}`);
        lines.push(`Règle : ${finding.rule_id || finding.metadata_json?.rule_id || "N/A"}`);
        lines.push(`Titre : ${finding.title || "N/A"}`);
        lines.push(`Fichier : ${finding.file_path || "N/A"}`);
        lines.push(`Ligne : ${finding.line_start || "N/A"}`);
        lines.push(`Sévérité : ${finding.severity || "N/A"}`);
        lines.push(`Catégorie OWASP : ${finding.owasp_id || "N/A"}`);
      } else if (fix) {
        lines.push(`Règle : ${fix.title}`);
        lines.push(`Fichier : ${fix.fileFull}`);
        lines.push(`Sévérité : ${fix.severity}`);
        lines.push(`Catégorie OWASP : ${fix.owasp}`);
      }
      lines.push("");
      if (fix) {
        lines.push("Code avant correction :");
        lines.push(`  ${fix.before.split("\n").join("\n  ")}`);
        lines.push("");
        lines.push("Code après correction :");
        lines.push(`  ${fix.after.split("\n").join("\n  ")}`);
      }
      lines.push("");
    }

    // Pied de page
    lines.push("-".repeat(80));
    lines.push("Généré par SecureScan - Plateforme d'Analyse de Qualité et Sécurité de Code");
    lines.push("=".repeat(80));

    const filename = `securescan_autofix_report_${date.toISOString().split("T")[0]}_PR${prResult?.pr?.number || ""}.txt`;
    downloadTextFile(lines.join("\n"), filename);
  };

  const handleAutoFix = async () => {
    if (!autoFixRepoUrl || !autoFixToken || !autoFixFindingId) {
      setAutoFixMessage("Renseigne l'URL du repo, le token GitHub et le finding_id.");
      return;
    }
    setAutoFixMessage("Création de la Pull Request en cours…");
    try {
      const res = await autoFixGithub({
        repo_url: autoFixRepoUrl.trim(),
        github_token: autoFixToken.trim(),
        finding_id: autoFixFindingId.trim(),
        base_branch: "main",
      });
      const prUrl = res?.pr?.url || res?.pr?.html_url || "";
      setAutoFixMessage(
        prUrl
          ? `Pull Request créée avec succès : ${prUrl}`
          : "Pull Request créée avec succès (voir GitHub)."
      );
      
      // Stocke le résultat pour pouvoir générer le rapport plus tard
      setLastAutoFixResult({ prResult: res, findingId: autoFixFindingId.trim() });
      
      // Génère automatiquement un rapport après la création de la PR
      if (res?.pr) {
        setTimeout(() => {
          generateAutoFixReport(res, autoFixFindingId.trim());
        }, 500);
      }
    } catch (e) {
      setAutoFixMessage(`Erreur auto-fix : ${e.message}`);
    }
  };

  const handleDownloadReport = () => {
    const lines = [];
    const date = new Date();
    const dateStr = formatDate(date);

    // En-tête
    lines.push("=".repeat(80));
    lines.push("SECURESCAN - RAPPORT DE SÉCURITÉ");
    lines.push("=".repeat(80));
    lines.push("");
    lines.push(`Date d'analyse : ${dateStr}`);
    lines.push(`Projet analysé : ${autoFixRepoUrl || "Non spécifié"}`);
    lines.push("");

    // Résumé
    lines.push("-".repeat(80));
    lines.push("RÉSUMÉ");
    lines.push("-".repeat(80));
    const selectedFixes = fixes.filter((f) => selected.has(f.id));
    lines.push(`Total de vulnérabilités sélectionnées : ${selectedFixes.length}`);
    
    const severityCounts = {};
    selectedFixes.forEach((f) => {
      severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
    });
    lines.push("");
    lines.push("Répartition par sévérité :");
    Object.entries(severityCounts).forEach(([sev, count]) => {
      lines.push(`  - ${sev}: ${count}`);
    });
    lines.push("");

    // Détails des corrections
    lines.push("-".repeat(80));
    lines.push("DÉTAILS DES CORRECTIONS");
    lines.push("-".repeat(80));
    lines.push("");

    if (selectedFixes.length === 0) {
      lines.push("Aucune correction sélectionnée.");
    } else {
      selectedFixes.forEach((f, idx) => {
        lines.push(`${idx + 1}. ${f.title}`);
        lines.push(`   Règle : ${f.title}`);
        lines.push(`   Fichier : ${f.fileFull}`);
        lines.push(`   Sévérité : ${f.severity}`);
        lines.push(`   Catégorie OWASP : ${f.owasp}`);
        if (f.findingId) {
          lines.push(`   ID de la vulnérabilité : ${f.findingId}`);
        }
        lines.push("");
        lines.push("   Code avant correction :");
        lines.push(`   ${f.before.split("\n").map((l) => `   ${l}`).join("\n")}`);
        lines.push("");
        lines.push("   Code après correction :");
        lines.push(`   ${f.after.split("\n").map((l) => `   ${l}`).join("\n")}`);
        lines.push("");
        lines.push("-".repeat(80));
        lines.push("");
      });
    }

    // Pull Requests créées
    if (createdPRs.length > 0 && createdPRs.some((p) => !p.error)) {
      lines.push("-".repeat(80));
      lines.push("PULL REQUESTS CRÉÉES");
      lines.push("-".repeat(80));
      lines.push("");
      createdPRs
        .filter((p) => !p.error)
        .forEach((pr, idx) => {
          lines.push(`${idx + 1}. ${pr.title}`);
          lines.push(`   Fichier : ${pr.file}`);
          lines.push(`   URL : ${pr.url}`);
          lines.push("");
        });
    }

    // Pied de page
    lines.push("-".repeat(80));
    lines.push("Généré par SecureScan - Plateforme d'Analyse de Qualité et Sécurité de Code");
    lines.push("=".repeat(80));

    const filename = `securescan_report_${date.toISOString().split("T")[0]}.txt`;
    downloadTextFile(lines.join("\n"), filename);
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
            Sélectionne des corrections à appliquer. Si tu renseignes l'URL du repo et le token GitHub ci-dessous, les corrections seront appliquées automatiquement via Pull Request.
          </p>
        </div>

        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          <button
            onClick={handleApply}
            disabled={!canApply}
            style={{
              backgroundColor: canApply ? (canDoRealFix ? "rgba(144, 238, 144, 0.25)" : "rgba(255, 182, 193, 0.25)") : "#e0e0e0",
              color: canApply ? (canDoRealFix ? "#1f7a3b" : "#c04c78") : "#999",
              border: canApply
                ? (canDoRealFix ? "1px solid rgba(144, 238, 144, 0.6)" : "1px solid rgba(255, 182, 193, 0.6)")
                : "1px solid #ddd",
              padding: "10px 14px",
              borderRadius: 14,
              cursor: canApply ? "pointer" : "not-allowed",
              fontWeight: 700,
            }}
          >
            {status === "applying"
              ? "Application..."
              : canDoRealFix
              ? "✅ Appliquer corrections (via GitHub)"
              : "Appliquer corrections (démo)"}
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

      {/* AUTO-FIX GITHUB */}
      <div
        style={{
          marginTop: 18,
          padding: 18,
          borderRadius: 18,
          backgroundColor: "#fff",
          boxShadow: "0 8px 30px rgba(0,0,0,0.04)",
          border: "1px solid #f1f1f1",
        }}
      >
        <h2 style={{ marginTop: 0, marginBottom: 10 }}>Auto-fix GitHub</h2>

        <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 10 }}>
          <div>
            <label style={{ fontSize: 13, fontWeight: 600, color: "#444" }}>URL du repository GitHub</label>
            <input
              type="text"
              placeholder="https://github.com/mon-user/mon-repo"
              value={autoFixRepoUrl}
              onChange={(e) => setAutoFixRepoUrl(e.target.value)}
              style={{
                marginTop: 4,
                width: "100%",
                padding: 10,
                borderRadius: 10,
                border: "1px solid #ddd",
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: 13, fontWeight: 600, color: "#444" }}>Token GitHub (PAT)</label>
            <input
              type="password"
              placeholder="ghp_…"
              value={autoFixToken}
              onChange={(e) => setAutoFixToken(e.target.value)}
              style={{
                marginTop: 4,
                width: "100%",
                padding: 10,
                borderRadius: 10,
                border: "1px solid #ddd",
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: 13, fontWeight: 600, color: "#444" }}>
              ID de la vulnérabilité à corriger
            </label>
            <input
              type="text"
              placeholder="Identifiant copié depuis la page /scans/{id}"
              value={autoFixFindingId}
              onChange={(e) => setAutoFixFindingId(e.target.value)}
              style={{
                marginTop: 4,
                width: "100%",
                padding: 10,
                borderRadius: 10,
                border: "1px solid #ddd",
              }}
            />
          </div>
        </div>

        <div style={{ marginTop: 14, display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <button
            onClick={handleAutoFix}
            style={{
              backgroundColor: "rgba(255, 182, 193, 0.25)",
              color: "#c04c78",
              border: "1px solid rgba(255, 182, 193, 0.6)",
              padding: "10px 16px",
              borderRadius: 14,
              cursor: "pointer",
              fontWeight: 700,
            }}
          >
            Lancer l'auto-fix GitHub
          </button>
          
          {lastAutoFixResult && lastAutoFixResult.prResult?.pr && (
            <button
              onClick={() => generateAutoFixReport(lastAutoFixResult.prResult, lastAutoFixResult.findingId)}
              style={{
                backgroundColor: "rgba(173, 216, 230, 0.25)",
                color: "#1f5fa8",
                border: "1px solid rgba(173, 216, 230, 0.6)",
                padding: "10px 16px",
                borderRadius: 14,
                cursor: "pointer",
                fontWeight: 700,
                fontSize: 13,
              }}
            >
              📄 Télécharger rapport PR
            </button>
          )}
          
          {autoFixMessage && (
            <span style={{ fontSize: 12, color: "#555", flex: "1 1 auto" }}>
              {autoFixMessage}
            </span>
          )}
        </div>
      </div>

      {/* STATUS */}
      {(status === "done" || status === "applied" || status === "error") && (
        <div
          style={{
            marginTop: 14,
            padding: 20,
            backgroundColor: status === "applied" ? "rgba(144, 238, 144, 0.1)" : status === "error" ? "rgba(255, 182, 193, 0.1)" : "white",
            borderRadius: 18,
            boxShadow: "0 8px 30px rgba(0,0,0,0.05)",
            border: `1px solid ${status === "applied" ? "rgba(144, 238, 144, 0.3)" : status === "error" ? "rgba(255, 182, 193, 0.3)" : "#f1f1f1"}`,
          }}
        >
          {status === "applied" && createdPRs.length > 0 ? (
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                <span style={{ fontSize: 20 }}>✅</span>
                <strong style={{ fontSize: 15, color: "#1f7a3b" }}>
                  Corrections appliquées via GitHub
                </strong>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {createdPRs
                  .filter((p) => !p.error)
                  .map((pr, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: 12,
                        backgroundColor: "white",
                        borderRadius: 10,
                        border: "1px solid #e5e5e5",
                      }}
                    >
                      <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>
                        {pr.title}
                      </div>
                      <div style={{ fontSize: 12, color: "#666", marginBottom: 6 }}>
                        {pr.file}
                      </div>
                      <a
                        href={pr.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 6,
                          fontSize: 13,
                          color: "#0366d6",
                          textDecoration: "none",
                          fontWeight: 600,
                        }}
                      >
                        <span>🔗</span>
                        <span>Pull Request #{pr.number}</span>
                        <span>→</span>
                      </a>
                    </div>
                  ))}
                {createdPRs.some((p) => p.error) && (
                  <div style={{ marginTop: 8, padding: 10, backgroundColor: "rgba(255, 182, 193, 0.1)", borderRadius: 8 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: "#b00020", marginBottom: 4 }}>
                      Erreurs :
                    </div>
                    {createdPRs
                      .filter((p) => p.error)
                      .map((pr, idx) => (
                        <div key={idx} style={{ fontSize: 11, color: "#666", marginTop: 4 }}>
                          • {pr.title} : {pr.message}
                        </div>
                      ))}
                  </div>
                )}
              </div>
            </div>
          ) : status === "error" ? (
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 20 }}>❌</span>
              <span style={{ color: "#b00020", fontWeight: 600 }}>
                Une erreur est survenue lors de l'application des corrections.
              </span>
            </div>
          ) : (
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 20 }}>ℹ️</span>
              <span style={{ color: "#666" }}>
                Corrections appliquées (mode démo uniquement).
              </span>
            </div>
          )}
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
            Aucun finding trouvé dans le résultat.
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
                        {fix.findingId && (
                          <div
                            style={{
                              marginTop: 6,
                              padding: "6px 10px",
                              backgroundColor: "#f5f5f5",
                              borderRadius: 6,
                              fontSize: 12,
                              display: "inline-flex",
                              alignItems: "center",
                              gap: 8,
                            }}
                          >
                            <span style={{ color: "#666", fontWeight: 600 }}>ID :</span>
                            <code
                              style={{
                                fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
                                color: "#c04c78",
                                fontWeight: 700,
                                fontSize: 11,
                              }}
                            >
                              {fix.findingId}
                            </code>
                            <button
                              onClick={() => {
                                navigator.clipboard.writeText(fix.findingId);
                                alert(`ID copié : ${fix.findingId}`);
                              }}
                              style={{
                                padding: "2px 8px",
                                fontSize: 10,
                                backgroundColor: "rgba(255, 182, 193, 0.2)",
                                border: "1px solid rgba(255, 182, 193, 0.4)",
                                borderRadius: 4,
                                cursor: "pointer",
                                color: "#c04c78",
                                fontWeight: 600,
                              }}
                            >
                              Copier
                            </button>
                          </div>
                        )}
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
      </div>
    </div>
  );
}