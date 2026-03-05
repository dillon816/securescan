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
    
    # Debug: affiche les valeurs pour comprendre pourquoi ça ne matche pas
    print(f"[DEBUG fix_rules] tool={tool}, rule_id={rule_id}, title={title}, file_path={file_path}")

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

    # RULE 7 — Bandit : yaml.load() sans Loader (désérialisation non sécurisée)
    if tool == "bandit" and ("yaml.load" in title or "yaml_load" in rule_id or "B506" in rule_id):
        if not target.exists():
            return {"ok": False, "rule": "classic:yaml_load_no_file", "modified_files": []}
        
        content = target.read_text(encoding="utf-8", errors="ignore")
        
        # Remplace yaml.load(...) par yaml.load(..., Loader=yaml.Loader)
        pat = re.compile(r"yaml\.load\s*\(([^)]+)\)", re.I)
        
        def yaml_fix(match):
            args = match.group(1).strip()
            # Si Loader est déjà présent, ne pas modifier
            if "Loader" in args:
                return match.group(0)
            return f"yaml.load({args}, Loader=yaml.Loader)"
        
        new_content, n = pat.subn(yaml_fix, content)
        if n > 0:
            target.write_text(new_content, encoding="utf-8")
            modified_files.append(file_path)
            return {
                "ok": True,
                "rule": "classic:yaml_load_secure",
                "modified_files": modified_files
            }

    # RULE 8 — Bandit : pickle.load() (désérialisation non sécurisée)
    if tool == "bandit" and ("pickle.load" in title or "pickle_load" in rule_id or "B301" in rule_id):
        if not target.exists():
            return {"ok": False, "rule": "classic:pickle_load_no_file", "modified_files": []}
        
        content = target.read_text(encoding="utf-8", errors="ignore")
        
        # Ajoute un commentaire de sécurité après pickle.load()
        pat = re.compile(r"(pickle\.load\s*\([^)]+\))", re.I)
        
        def pickle_fix(match):
            return f"{match.group(1)}  # WARNING: Only load trusted data"
        
        new_content, n = pat.subn(pickle_fix, content)
        if n > 0:
            target.write_text(new_content, encoding="utf-8")
            modified_files.append(file_path)
            return {
                "ok": True,
                "rule": "classic:pickle_load_warning",
                "modified_files": modified_files
            }

    # RULE 9 — Bandit : eval() et exec() (exécution de code)
    if tool == "bandit" and ("eval" in title or "exec" in title or "B307" in rule_id or "B102" in rule_id):
        if not target.exists():
            return {"ok": False, "rule": "classic:eval_exec_no_file", "modified_files": []}
        
        # Remplace eval(...) par ast.literal_eval(...) si possible
        # Sinon ajoute un commentaire de sécurité
        content = target.read_text(encoding="utf-8", errors="ignore")
        
        # Remplace eval( par ast.literal_eval( (plus sûr pour les littéraux)
        eval_pat = re.compile(r"eval\s*\(", re.I)
        if eval_pat.search(content):
            # Ajoute l'import ast si nécessaire
            if "import ast" not in content and "from ast import" not in content:
                # Trouve la première ligne d'import
                lines = content.split('\n')
                import_idx = 0
                for i, line in enumerate(lines):
                    if line.strip().startswith('import ') or line.strip().startswith('from '):
                        import_idx = i + 1
                        break
                lines.insert(import_idx, "import ast")
                content = '\n'.join(lines)
            
            # Remplace eval( par ast.literal_eval(
            new_content = eval_pat.sub("ast.literal_eval(", content)
            if new_content != content:
                target.write_text(new_content, encoding="utf-8")
                modified_files.append(file_path)
                return {
                    "ok": True,
                    "rule": "classic:eval_to_ast_literal",
                    "modified_files": modified_files
                }
        
        # Pour exec(), ajoute juste un commentaire de sécurité
        exec_pat = re.compile(r"exec\s*\(", re.I)
        if exec_pat.search(content):
            new_content = exec_pat.sub("exec(  # SECURITY WARNING: Only execute trusted code", content)
            if new_content != content:
                target.write_text(new_content, encoding="utf-8")
                modified_files.append(file_path)
                return {
                    "ok": True,
                    "rule": "classic:exec_warning",
                    "modified_files": modified_files
                }

    # RULE 10 — Bandit : subprocess avec shell=True
    if tool == "bandit" and ("shell=True" in title or "shell=true" in title or "B602" in rule_id):
        if not target.exists():
            return {"ok": False, "rule": "classic:subprocess_shell_no_file", "modified_files": []}
        
        # Remplace shell=True par shell=False et ajuste la commande
        pat = re.compile(r"shell\s*=\s*True", re.I)
        
        if _replace_in_file(target, pat, "shell=False"):
            modified_files.append(file_path)
            return {
                "ok": True,
                "rule": "classic:subprocess_shell_false",
                "modified_files": modified_files
            }

    # RULE 11 — Semgrep/Bandit : MD5 et autres hash non sécurisés
    # Détection très permissive pour capturer toutes les variantes
    title_lower = title.lower()
    rule_id_lower = rule_id.lower()
    file_lower = file_path.lower()
    
    # Détecte MD5 dans le titre, rule_id, ou si c'est un fichier Python
    # Vérifie aussi les variantes comme "insecure-hash-algorithm", "hash-algorithms-md5", etc.
    is_md5_issue = (
        "md5" in title_lower or 
        "md5" in rule_id_lower or 
        "insecure-hash" in rule_id_lower or 
        "insecure-hash-algorithm" in rule_id_lower or
        "insecure-hash-algorithms" in rule_id_lower or
        "hash-algorithm" in rule_id_lower or
        "hash-algorithms" in rule_id_lower or
        "B303" in rule_id_lower
    )
    
    # Si c'est un fichier Python ET qu'on détecte un problème de hash, applique la correction
    if is_md5_issue and file_lower.endswith(".py"):
        if not target.exists():
            return {"ok": False, "rule": "classic:md5_no_file", "modified_files": []}
        
        content = target.read_text(encoding="utf-8", errors="ignore")
        original_content = content
        
        # Remplace hashlib.md5() par hashlib.sha256()
        md5_pat = re.compile(r"hashlib\.md5\s*\(", re.I)
        if md5_pat.search(content):
            # Ajoute l'import hashlib si nécessaire
            if "import hashlib" not in content and "from hashlib import" not in content:
                lines = content.split('\n')
                import_idx = 0
                for i, line in enumerate(lines):
                    if line.strip().startswith('import ') or line.strip().startswith('from '):
                        import_idx = i + 1
                        break
                lines.insert(import_idx, "import hashlib")
                content = '\n'.join(lines)
            
            content = md5_pat.sub("hashlib.sha256(", content)
        
        # Remplace md5() direct par sha256()
        md5_direct_pat = re.compile(r"\.md5\s*\(", re.I)
        content = md5_direct_pat.sub(".sha256(", content)
        
        # Remplace import md5 par import hashlib
        import_md5_pat = re.compile(r"import\s+md5\b", re.I)
        if import_md5_pat.search(content):
            content = import_md5_pat.sub("import hashlib", content)
            # Remplace md5.new() par hashlib.sha256()
            content = re.sub(r"md5\.new\s*\(", "hashlib.sha256(", content, flags=re.I)
        
        # Si le contenu a changé, sauvegarde
        if content != original_content:
            target.write_text(content, encoding="utf-8")
            modified_files.append(file_path)
            return {
                "ok": True,
                "rule": "classic:md5_to_sha256",
                "modified_files": modified_files
            }
        
        # Fallback : même si on ne trouve pas le pattern exact, on ajoute un commentaire de sécurité
        # à la ligne concernée
        if finding.get("line"):
            try:
                line_num = int(finding.get("line"))
                lines = content.split('\n')
                if 0 < line_num <= len(lines):
                    # Ajoute un commentaire de sécurité sur la ligne précédente
                    lines.insert(line_num - 1, f"# SECURITY: MD5 is insecure, use hashlib.sha256() instead")
                    target.write_text('\n'.join(lines), encoding="utf-8")
                    modified_files.append(file_path)
                    return {
                        "ok": True,
                        "rule": "classic:md5_security_comment",
                        "modified_files": modified_files
                    }
            except (ValueError, IndexError):
                pass

    # RULE 12 — Semgrep : hardcoded secrets/passwords
    if tool == "semgrep" and ("hardcoded" in title or "secret" in title or "password" in title or "api_key" in title):
        if not target.exists():
            return {"ok": False, "rule": "classic:hardcoded_secret_no_file", "modified_files": []}
        
        content = target.read_text(encoding="utf-8", errors="ignore")
        
        # Remplace les valeurs hardcodées par des variables d'environnement
        # Pattern: variable = "secret_value" ou variable = 'secret_value'
        secret_pat = re.compile(r'(\w+)\s*=\s*["\']([^"\']{10,})["\']', re.I)
        
        def secret_fix(match):
            var_name = match.group(1)
            # Garde seulement si ça ressemble à un secret (longueur > 10)
            return f'{var_name} = os.getenv("{var_name.upper()}", "")  # TODO: Move to environment variable'
        
        new_content, n = secret_pat.subn(secret_fix, content)
        if n > 0:
            # Ajoute l'import os si nécessaire
            if "import os" not in content and "from os import" not in content:
                lines = new_content.split('\n')
                import_idx = 0
                for i, line in enumerate(lines):
                    if line.strip().startswith('import ') or line.strip().startswith('from '):
                        import_idx = i + 1
                        break
                lines.insert(import_idx, "import os")
                new_content = '\n'.join(lines)
            
            target.write_text(new_content, encoding="utf-8")
            modified_files.append(file_path)
            return {
                "ok": True,
                "rule": "classic:hardcoded_secret_to_env",
                "modified_files": modified_files
            }

    # FALLBACK : Si c'est un fichier Python et qu'on n'a rien trouvé, essaie au moins d'ajouter un commentaire
    # à la ligne concernée pour indiquer qu'il y a un problème de sécurité
    if file_path.lower().endswith(".py") and finding.get("line"):
        if target.exists():
            try:
                line_num = int(finding.get("line"))
                content = target.read_text(encoding="utf-8", errors="ignore")
                lines = content.split('\n')
                if 0 < line_num <= len(lines):
                    # Ajoute un commentaire de sécurité sur la ligne précédente
                    comment = f"# SECURITY FIX: {title[:50]} - Review and fix manually"
                    if line_num > 0 and not lines[line_num - 1].strip().startswith('#'):
                        lines.insert(line_num - 1, comment)
                        target.write_text('\n'.join(lines), encoding="utf-8")
                        modified_files.append(file_path)
                        print(f"[DEBUG fix_rules] Applied fallback security comment at line {line_num}")
                        return {
                            "ok": True,
                            "rule": "classic:fallback_security_comment",
                            "modified_files": modified_files
                        }
            except (ValueError, IndexError, Exception) as e:
                print(f"[DEBUG fix_rules] Fallback failed: {e}")
    
    # Aucune règle n'a matché → pas de correction automatique
    print(f"[DEBUG fix_rules] No rule matched. tool={tool}, rule_id={rule_id}, title={title}, file_path={file_path}")
    return {
        "ok": False,
        "rule": "classic:none",
        "modified_files": []
    }