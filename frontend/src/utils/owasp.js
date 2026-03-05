// Extrait le code OWASP depuis les métadonnées
export function pickOwasp(item) {
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
