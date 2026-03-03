if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

# install requirements.txt
py -m pip install -r requirements.txt

# run main
python -m app.main

# Installer DB
pip install sqlalchemy psycopg2-binary python-dotenv

```markdown

## Arborescence du Dépôt

```text
securescan-hkt/
│
├── frontend/               # Interface utilisateur (React / Vue.js)
│   ├── public/
│   ├── src/
│   │   ├── assets/         # Images, icônes, styles globaux
│   │   ├── components/     # Composants réutilisables (Navbar, Cards, Buttons)
│   │   ├── pages/          # Vues principales (Accueil, Dashboard, Corrections)
│   │   ├── services/       # Appels API vers le backend (Axios/Fetch)
│   │   └── App.jsx         # Point d'entrée et routing
│   ├── package.json
│   └── .env.example    
│
├── backend/                # API REST, Logique métier et Base de données (FastAPI) [cite: 289, 326]
│   ├── app/
│   │   ├── main.py         # Point d'entrée de l'application FastAPI
│   │   ├── api/            # Routes de l'API (ex: /scan, /fix, /report)
│   │   ├── models/         # Modèles de base de données (SQLAlchemy) 
│   │   ├── services/       # Cœur de la logique métier :
│   │   │   ├── scanner_orchestrator.py # Lancement CLI (Semgrep, Bandit, TruffleHog)
│   │   │   ├── git_service.py          # Clonage, création de branches, push automatisé
│   │   │   └── owasp_mapper.py         # Logique de classification OWASP Top 10
│   │   └── core/           # Configuration globale (CORS, Base de données)
│   ├── temp_repos/         # Dossier éphémère pour le clonage des dépôts analysés
│   ├── requirements.txt    # Dépendances Python
│   └── .env.example        # Template pour DB_URL, GITHUB_TOKEN (Ne pas commit le vrai .env !)
│
├── .gitignore              # Exclusion des fichiers sensibles et dossiers inutiles (node_modules, venv, .env)
└── README.md               # Documentation du projet

```
