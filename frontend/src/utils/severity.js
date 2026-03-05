// Convertit une sévérité en format standardisé
export function normalizeSeverity(raw) {
  const s = String(raw || "medium").toLowerCase();
  if (s.includes("critical")) return "Critical";
  if (s.includes("high") || s === "error") return "High";
  if (s.includes("low")) return "Low";
  if (s.includes("medium") || s === "warning" || s.includes("warn")) return "Medium";
  return "Info";
}
