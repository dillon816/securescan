// Raccourcit un chemin de fichier si trop long
export function shortPath(p) {
  if (!p) return "—";
  const max = 80;
  if (p.length <= max) return p;
  return "…" + p.slice(p.length - max);
}
