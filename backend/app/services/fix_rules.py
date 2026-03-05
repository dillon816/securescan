from __future__ import annotations
from pathlib import Path
import re


# Ajoute une ligne dans un fichier si elle n'existe pas déjà
# Exemple : ajouter ".env" dans .gitignore
def _ensure_line_in_file(path: Path, line: str) -> bool:
    # Si le fichier n'existe pas on le crée directement
    if not path.exists():
        path.write_text(line + "\n", encoding="utf-8")
        return True

    # Lecture du fichier ligne par ligne
    content = path.read_text(encoding="utf-8", errors="ignore").splitlines()

    # Si la ligne est déjà présente → rien à faire
    if line in content:
        return False

    # Sinon on l'ajoute à la fin
    content.append(line)

    # Réécriture du fichier avec la nouvelle ligne
    path.write_text("\n".join(content) + "\n", encoding="utf-8")

    return True


# Supprime toutes les lignes correspondant à un pattern (regex)
# Utilisé par exemple pour supprimer des secrets dans un fichier
def _remove_lines_matching(path: Path, pattern: re.Pattern) -> bool:
    # Si le fichier n'existe pas on ne fait rien
    if not path.exists():
        return False

    # Lecture des lignes du fichier
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()

    # On garde seulement les lignes qui ne correspondent pas au pattern
    new_lines = [l for l in lines if not pattern.search(l)]

    # Vérifie si le fichier a changé
    changed = (new_lines != lines)

    # Si oui on réécrit le fichier
    if changed:
        path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    return changed


# Remplace un pattern dans un fichier par une autre chaîne
# Utilisé pour appliquer des corrections automatiques dans le code
def _replace_in_file(path: Path, pattern: re.Pattern, repl: str) -> bool:
    # Si le fichier n'existe pas on arrête
    if not path.exists():
        return False

    # Lecture complète du fichier
    content = path.read_text(encoding="utf-8", errors="ignore")

    # Remplacement via regex
    new_content, n = pattern.subn(repl, content)

    # Si au moins un remplacement a été fait
    if n > 0:
        path.write_text(new_content, encoding="utf-8")
        return True

    return False


# Fonction principale qui applique un correctif automatique
# à partir d'un finding détecté par les outils de scan
def apply_classic_fix(repo_dir: Path, finding: dict) -> dict:
    """
    Retourne:
    {
      "ok": bool,
      "rule": str,
      "modified_files": [..]
    }
    """

    # Récupération des informations du finding
    # file_path = chemin du fichier vulnérable
    # rule_id = règle de sécurité déclenchée
    # tool = outil qui a détecté la vulnérabilité
    # title = description de la vulnérabilité
    file_path = (finding.get("file_path") or finding.get("file") or "").lstrip("/")
    rule_id = (finding.get("rule_id") or "").lower()
    tool = (finding.get("tool") or "").lower()
    title = (finding.get("title") or "").lower()

    # Liste des fichiers modifiés par le fix
    modified_files: list[str] = []

    # Liste des chemins qu'on ne veut jamais modifier
    # (dépendances externes ou fichiers générés)
    blocked_paths = (
        "node_modules/",
        "vendor/",
        "dist/",
        "build/",
        "assets/vendor/",
        "public/assets/vendor/"
    )

    # Si le fichier appartient à ces dossiers → on bloque le fix
    if any(p in file_path for p in blocked_paths):
        return {
            "ok": False,
            "rule": "classic:blocked_path",
            "modified_files": []
        }

    # Chemin complet du fichier dans le repo cloné
    target = repo_dir / file_path

       # RULE 1 — Secrets (.env) :
    # Si TruffleHog détecte un secret (ou si on touche un .env), on supprime les lignes sensibles
    # puis on s'assure que le .env est ignoré par Git.
    if tool == "trufflehog" or file_path.endswith(".env"):

        # Pattern simple pour repérer des clés/tokens fréquents dans un fichier
        pat = re.compile(
            r"(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|SECRET|TOKEN)\s*=",
            re.I
        )

        # Supprime les lignes qui matchent le pattern (évite de commiter des secrets)
        changed = _remove_lines_matching(target, pat)

        if changed:
            modified_files.append(file_path)

        # Ajoute ".env" dans .gitignore pour éviter une ré-exposition future
        gitignore = repo_dir / ".gitignore"

        if _ensure_line_in_file(gitignore, ".env"):
            modified_files.append(".gitignore")

        return {
            "ok": len(modified_files) > 0,
            "rule": "classic:secrets_env",
            "modified_files": modified_files
        }

    # RULE 2 — XSS (innerHTML) :
    # innerHTML peut injecter du HTML/JS si la valeur est contrôlée → on remplace par textContent.
    if "innerhtml" in title or "insecure-document-method" in rule_id:

        # Remplacement ciblé : .innerHTML = ...  ->  .textContent = ...
        pat = re.compile(r"\.innerHTML(\s*=\s*)", re.I)

        if _replace_in_file(target, pat, ".textContent\\1"):

            modified_files.append(file_path)

            return {
                "ok": True,
                "rule": "classic:innerhtml_to_textcontent",
                "modified_files": modified_files
            }

    # RULE 3 — unlink(user input) :
    # unlink() avec une entrée utilisateur peut supprimer des fichiers hors du dossier attendu.
    # On force un dossier de base + basename() pour éviter les traversées de chemin.
    if "unlink-use" in rule_id:

        # Si le fichier n'existe pas → rien à corriger
        if not target.exists():
            return {
                "ok": False,
                "rule": "classic:unlink_use",
                "modified_files": []
            }

        content = target.read_text(encoding="utf-8", errors="ignore")

        # Supporte aussi "@unlink(...)" (sinon on laisse un "@" isolé en PHP)
        unlink_pattern = re.compile(r'(^[ \t]*)@?\s*unlink\((.*?)\)\s*;\s*$', re.M)

        def secure_replace(match):
            indent = match.group(1) or ""
            arg = match.group(2)

            # Correction template : dossier fixe + basename() + vérification file_exists()
            return (
                f"{indent}$baseDir = $this->getParameter('kernel.project_dir') . '/public/uploads';\n\n"
                f"{indent}$name = basename({arg});\n\n"
                f"{indent}$file = $baseDir . '/' . $name;\n\n"
                f"{indent}if (file_exists($file)) {{\n"
                f"{indent}    unlink($file);\n"
                f"{indent}}}\n"
            )

        new_content, n = unlink_pattern.subn(secure_replace, content)

        if n > 0:
            target.write_text(new_content, encoding="utf-8")
            modified_files.append(file_path)

            return {
                "ok": True,
                "rule": "classic:secure_unlink",
                "modified_files": modified_files
            }

    # RULE 4 — XSS (echo PHP) :
    # Si Semgrep détecte un cas XSS basique, on échappe la sortie HTML.
    if tool == "semgrep" and "xss" in title:

        # Cas très simple : echo $var  -> echo htmlspecialchars($var, ...)
        pat = re.compile(r"echo\s+\$(\w+)")

        if _replace_in_file(
            target,
            pat,
            r'echo htmlspecialchars($\1, ENT_QUOTES, "UTF-8")'
        ):
            modified_files.append(file_path)

            return {
                "ok": True,
                "rule": "classic:htmlspecialchars",
                "modified_files": modified_files
            }

    # RULE 5 — SQL Injection :
    # Remplace une concat SQL basique par une requête préparée (template PDO).
    if "sql" in title or "sql-injection" in rule_id:

        if not target.exists():
            return {
                "ok": False,
                "rule": "classic:sql_injection",
                "modified_files": []
            }

        content = target.read_text(encoding="utf-8", errors="ignore")

        # on applique ce template uniquement si le fichier semble utiliser PDO ($pdo)
        if "$pdo" not in content:
            return {
                "ok": False,
                "rule": "classic:sql_injection_no_pdo_context",
                "modified_files": []
            }

        # Pattern : "SELECT ... " . $_GET['x']  (ou $_POST)
        sql_pattern = re.compile(
            r'"(\s*SELECT[^"]*?)"\s*\.\s*\$_(GET|POST)\s*\[\s*([^\]]+)\s*\]',
            re.I
        )

        def _clean_key(k: str) -> str:
            # Normalise la clé (enlève les quotes si présentes)
            kk = (k or "").strip()
            if (kk.startswith("'") and kk.endswith("'")) or (kk.startswith('"') and kk.endswith('"')):
                kk = kk[1:-1].strip()
            return kk

        def sql_fix(match):
            select_part = match.group(1)
            method = (match.group(2) or "GET").upper()
            raw_key = match.group(3)
            key = _clean_key(raw_key)

            # Template PDO : placeholder + execute()
            return (
                f'$stmt = $pdo->prepare("{select_part}?");\n'
                f'$stmt->execute([$_{method}["{key}"]]);'
            )

        new_content, n = sql_pattern.subn(sql_fix, content)

        if n > 0:
            target.write_text(new_content, encoding="utf-8")
            modified_files.append(file_path)

            return {
                "ok": True,
                "rule": "classic:sql_injection_fix",
                "modified_files": modified_files
            }

    # RULE 6 — Debug (.env) :
    # Empêche APP_DEBUG=true (risque d'exposer des infos sensibles en prod).
    if file_path.endswith(".env"):

        pat = re.compile(r"APP_DEBUG\s*=\s*true", re.I)

        if _replace_in_file(target, pat, "APP_DEBUG=false"):

            modified_files.append(file_path)

            return {
                "ok": True,
                "rule": "classic:disable_debug",
                "modified_files": modified_files
            }

    # Aucune règle n'a matché → pas de correction automatique
    return {
        "ok": False,
        "rule": "classic:none",
        "modified_files": []
    }