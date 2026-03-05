# 🛡️ SecureScan

**Plateforme d'Analyse de Qualité et Sécurité de Code**

Projet développé dans le cadre du **Hackathon IPSSI 2026** - Équipe 18

SecureScan est une plateforme complète permettant d'analyser automatiquement la sécurité de projets de code source, de détecter les vulnérabilités selon les standards OWASP Top 10:2025, et de proposer des corrections automatiques via Pull Requests GitHub.

## ✨ Fonctionnalités principales

- 🔍 **Analyse multi-outils** : Semgrep (SAST), Bandit (Python), TruffleHog (secrets)
- 📊 **Dashboard interactif** : Visualisation des vulnérabilités avec filtres et score de sécurité
- 🎯 **Mapping OWASP Top 10:2025** : Classification automatique des vulnérabilités
- 🤖 **Auto-fix GitHub** : Création automatique de Pull Requests pour corriger les vulnérabilités
- 📄 **Génération de rapports** : Export des résultats en format texte professionnel
- 🔐 **Support repos privés** : Analyse de repositories GitHub privés via token
- 📦 **Support ZIP** : Analyse de projets uploadés en fichier ZIP

## 🚀 Installation

### Prérequis

**Backend :**
- Python 3.9+
- Git
- MySQL installé et en cours d'exécution
- Outils de sécurité :
  - Semgrep : `pip install semgrep` ou `brew install semgrep`
  - Bandit : `pip install bandit`
  - TruffleHog : `pip install trufflehog` ou `brew install trufflehog`

**Frontend :**
- Node.js 14+
- npm ou yarn

### Installation complète

1. **Cloner le repository**
```bash
git clone https://github.com/dillon816/securescan.git
cd securescan
```

2. **Installer le backend**
```bash
cd backend
python3 -m pip install -r requirements.txt
```

3. **Installer le frontend**
```bash
cd ../frontend
npm install
```

4. **Configurer la base de données MySQL**

Crée la base de données :
```sql
CREATE DATABASE securescan CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Crée un fichier `.env` dans le dossier `backend/` :
```bash
DATABASE_URL=mysql+pymysql://user:password@localhost:3306/securescan
REACT_APP_API_URL=http://localhost:8001
```

Remplace `user`, `password`, `localhost`, `3306` et `securescan` par tes propres paramètres MySQL.

## 🎮 Lancement

### 1. Démarrer le backend

```bash
cd backend
python3 -m uvicorn app.main:app --reload --port 8001
```

Le backend sera disponible sur [http://localhost:8001](http://localhost:8001)  
Documentation API : [http://localhost:8001/docs](http://localhost:8001/docs)

### 2. Démarrer le frontend

Dans un **nouveau terminal** :

```bash
cd frontend
npm start
```

Le frontend s'ouvrira automatiquement sur [http://localhost:3000](http://localhost:3000)

## 🛠️ Stack technique

### Backend
- **FastAPI** - Framework web moderne et performant
- **SQLAlchemy** - ORM pour la gestion de la base de données
- **Pydantic** - Validation et sérialisation des données
- **Uvicorn** - Serveur ASGI haute performance
- **MySQL** - Base de données relationnelle pour stocker scans et findings
- **PyMySQL** - Driver MySQL pour Python

### Frontend
- **React 19** - Bibliothèque UI moderne
- **React Router DOM** - Navigation entre pages
- **Fetch API** - Communication avec le backend

### Outils de sécurité
- **Semgrep** - Analyse statique de code (SAST)
- **Bandit** - Analyse de sécurité Python
- **TruffleHog** - Détection de secrets et credentials

## 🏗️ Architecture

```
securescan/
├── backend/              # API FastAPI
│   ├── app/
│   │   ├── api/         # Routes API
│   │   │   └── routes.py
│   │   ├── core/        # Utilitaires (Git, ZIP, CORS)
│   │   │   ├── cors.py
│   │   │   ├── git_utils.py
│   │   │   └── zip_utils.py
│   │   ├── db/          # Modèles et configuration DB
│   │   │   ├── database.py
│   │   │   └── models.py
│   │   ├── models/      # Schémas Pydantic
│   │   │   └── schemas.py
│   │   ├── security/    # Normalisation et mapping OWASP
│   │   │   ├── normalizer.py
│   │   │   └── owasp_mapper.py
│   │   ├── services/    # Services d'analyse et auto-fix
│   │   │   ├── semgrep_service.py
│   │   │   ├── bandit_service.py
│   │   │   ├── trufflehog_service.py
│   │   │   ├── fix_rules.py
│   │   │   ├── git_patch_service.py
│   │   │   └── github_pr_service.py
│   │   └── main.py      # Point d'entrée FastAPI
│   └── requirements.txt
│
├── frontend/             # Application React
│   ├── src/
│   │   ├── api/         # Client HTTP
│   │   │   ├── client.js
│   │   │   └── scans.js
│   │   ├── components/  # Composants réutilisables
│   │   │   ├── SeverityBadge.jsx
│   │   │   ├── OwaspBadge.jsx
│   │   │   ├── CodeBox.jsx
│   │   │   ├── SidebarLayout.jsx
│   │   │   └── index.js
│   │   ├── pages/       # Pages principales
│   │   │   ├── Upload.jsx
│   │   │   ├── Scan.jsx
│   │   │   ├── Dashboard.jsx
│   │   │   └── Fixes.jsx
│   │   ├── utils/       # Fonctions utilitaires
│   │   │   ├── severity.js
│   │   │   ├── owasp.js
│   │   │   ├── paths.js
│   │   │   ├── reports.js
│   │   │   └── index.js
│   │   ├── constants/   # Constantes (styles, etc.)
│   │   │   └── styles.js
│   │   ├── App.js       # Configuration des routes
│   │   ├── index.js     # Point d'entrée React
│   │   └── index.css    # Styles globaux
│   └── package.json
│
└── README.md
```

## 🎯 Choix techniques

### Pourquoi FastAPI ?
- **Performance** : Basé sur Starlette et Pydantic, très rapide
- **Documentation automatique** : Swagger UI intégré
- **Type hints** : Support natif de Python pour la validation
- **Asynchrone** : Support natif de l'asyncio pour les opérations I/O

### Pourquoi React ?
- **Écosystème riche** : Nombreuses bibliothèques disponibles
- **Composants réutilisables** : Architecture modulaire
- **Performance** : Virtual DOM et optimisations automatiques
- **Communauté** : Large communauté et support

### Pourquoi MySQL ?
- **Performance** : Base de données relationnelle performante pour gérer de gros volumes
- **JSON natif** : Support natif du type JSON pour stocker les métadonnées complexes
- **Scalabilité** : Peut gérer plusieurs utilisateurs et scans simultanés
- **Production-ready** : Base de données robuste adaptée à un environnement de production
- **Indexation** : Index optimisés pour les recherches rapides sur les findings

### Pourquoi ces outils de sécurité ?
- **Semgrep** : Détecte un large éventail de vulnérabilités dans plusieurs langages
- **Bandit** : Spécialisé Python, complémentaire à Semgrep
- **TruffleHog** : Détection de secrets (tokens, clés API, mots de passe)

## 📋 Workflow d'utilisation

1. **Upload** : L'utilisateur upload un ZIP ou fournit une URL Git
2. **Analyse** : Le backend lance Semgrep, Bandit et TruffleHog en parallèle
3. **Normalisation** : Les résultats sont normalisés et mappés à OWASP Top 10:2025
4. **Stockage** : Les findings sont sauvegardés en base de données MySQL
5. **Visualisation** : Le dashboard affiche les résultats avec filtres et score
6. **Correction** : L'utilisateur peut sélectionner des vulnérabilités et créer des PR GitHub automatiquement

## 📡 API Endpoints

### Santé
- `GET /health` - Vérifie l'état de l'API

### Scans individuels (ZIP)
- `POST /scan/semgrep` - Lance Semgrep sur un ZIP
- `POST /scan/bandit` - Lance Bandit sur un ZIP
- `POST /scan/trufflehog` - Lance TruffleHog sur un ZIP

### Scans individuels (Git)
- `POST /scan/semgrep/git` - Lance Semgrep sur un repo Git
- `POST /scan/bandit/git` - Lance Bandit sur un repo Git
- `POST /scan/trufflehog/git` - Lance TruffleHog sur un repo Git

### Scans complets
- `POST /scan/all` - Lance tous les outils en parallèle sur un ZIP
- `POST /scan/all/git` - Lance tous les outils en parallèle sur un repo Git

### Gestion des scans
- `GET /scans` - Liste les scans récents
- `GET /scans/{scan_id}` - Récupère les détails d'un scan avec ses findings
- `GET /stats` - Statistiques globales sur les scans

### Rapports
- `GET /report/{scan_id}` - Génère un rapport HTML pour un scan

### Auto-fix
- `POST /fix/auto/github` - Crée une Pull Request GitHub pour corriger une vulnérabilité
- `POST /fix/apply/github` - Applique une correction via GitHub (endpoint alternatif)

Documentation interactive : [http://localhost:8001/docs](http://localhost:8001/docs)

## 🗄️ Base de données

La base de données MySQL stocke :

- **Scans** - Historique des analyses effectuées
- **Findings** - Vulnérabilités détectées avec leurs détails (fichier, ligne, sévérité, OWASP)
- **FixSuggestions** - Suggestions de corrections
- **FixRuns** - Historique des corrections appliquées (Pull Requests créées)

Les tables sont créées automatiquement au premier démarrage grâce à SQLAlchemy.

## 🎨 Frontend - Pages principales

1. **Upload** (`/`) - Page d'accueil
   - Upload d'un fichier ZIP
   - Analyse d'un repository Git (public ou privé avec token)
   - Lancement de l'analyse avec Semgrep, Bandit et TruffleHog

2. **Scan** (`/scan`) - Page de progression
   - Affichage de la progression du scan
   - Animation des outils en cours d'exécution
   - Redirection automatique vers le dashboard

3. **Dashboard** (`/dashboard`) - Résultats d'analyse
   - Affichage de tous les findings détectés
   - Filtrage par outil, sévérité, OWASP
   - Score de sécurité calculé
   - Navigation vers les corrections

4. **Fixes** (`/fixes`) - Corrections et rapports
   - Liste des corrections proposées
   - Sélection de corrections à appliquer
   - Auto-fix GitHub (création de Pull Requests)
   - Génération de rapports texte

### Composants réutilisables
- **SeverityBadge** - Badge coloré selon la sévérité
- **OwaspBadge** - Badge avec code OWASP
- **CodeBox** - Affichage de code formaté
- **SidebarLayout** - Layout avec sidebar de navigation responsive

## 🔐 Configuration GitHub

Pour analyser des repositories privés et créer des Pull Requests :

1. Crée un **Personal Access Token (PAT)** sur GitHub
   - GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Permissions nécessaires : `repo` (accès complet aux repositories)
3. Utilise le token dans l'interface lors de l'analyse Git
  
Pour analyser des repositories privés et créer des Pull Requests, SecureScan utilise un **GitHub Personal Access Token (Fine-grained)**.

1. Aller sur **GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens**
2. Cliquer sur **Generate new token**
3. Sélectionner le repository à analyser

Permissions nécessaires :

- **Contents** → Read and write  
- **Metadata** → Read-only  
- **Pull requests** → Read-only  

Le token peut ensuite être utilisé dans SecureScan pour analyser le repository et créer automatiquement une Pull Request avec les correctifs.

⚠️ **Sécurité** : Le token n'est jamais stocké, uniquement transmis au backend pour les opérations Git.

## 📝 Variables d'environnement

**Backend** (fichier `backend/.env`) :
- `DATABASE_URL` - URL de connexion MySQL (format: `mysql+pymysql://user:password@host:port/database`)
- `REACT_APP_API_URL` - URL du backend (pour CORS)

**Frontend** (fichier `frontend/.env`) :
- `REACT_APP_API_URL` - URL du backend (défaut: `http://localhost:8001`)

## 🐛 Dépannage

### Erreur "command not found: semgrep"
Installe Semgrep : `pip install semgrep` ou `brew install semgrep`

### Erreur "No module named uvicorn"
Installe les dépendances : `python3 -m pip install -r requirements.txt`

### Erreur de connexion à la base de données
Vérifie que :
1. MySQL est installé et en cours d'exécution
2. La base de données `securescan` existe
3. Le fichier `.env` contient la bonne `DATABASE_URL` MySQL
4. `pymysql` est installé : `pip install pymysql`

### Erreur CORS
Assure-toi que `REACT_APP_API_URL` dans `.env` correspond à l'URL du frontend

### Erreur "f-string expression part cannot include a backslash"
Assure-toi d'utiliser Python 3.9+ et que le code utilise `Optional[str]` au lieu de `str | None`

## 🔧 Scripts disponibles

**Backend :**
- `python3 -m uvicorn app.main:app --reload --port 8001` - Lance le serveur de développement

**Frontend :**
- `npm start` - Lance le serveur de développement
- `npm run build` - Crée un build de production
- `npm test` - Lance les tests (si configurés)

## 🤝 Contribution

Projet développé par l'**Équipe 18** dans le cadre du Hackathon IPSSI 2026.

## 📝 Licence

Ce projet est développé dans le cadre d'un hackathon éducatif.

---

**Made with ❤️ by Team 18 - Hackathon IPSSI 2026**
