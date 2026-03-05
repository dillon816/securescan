# Structure du Frontend SecureScan

## Organisation des dossiers

```
src/
├── components/          # Composants React réutilisables
│   ├── SeverityBadge.jsx
│   ├── OwaspBadge.jsx
│   ├── CodeBox.jsx
│   └── index.js         # Exports centralisés
│
├── pages/               # Pages principales de l'application
│   ├── Upload.jsx       # Page de soumission (ZIP/Git)
│   ├── Scan.jsx         # Page d'attente pendant le scan
│   ├── Dashboard.jsx    # Dashboard avec résultats
│   └── Fixes.jsx        # Page de corrections & rapports
│
├── api/                  # Appels API vers le backend
│   ├── client.js        # Client HTTP de base
│   ├── scan.js          # Endpoints de scan
│   └── scans.js         # Endpoints de scans & auto-fix
│
├── utils/               # Fonctions utilitaires
│   ├── severity.js      # Normalisation des sévérités
│   ├── owasp.js         # Extraction codes OWASP
│   ├── paths.js         # Utilitaires pour les chemins
│   ├── reports.js       # Génération de rapports
│   └── index.js         # Exports centralisés
│
├── constants/           # Constantes réutilisables
│   └── styles.js        # Couleurs, ombres, bordures
│
├── App.js               # Configuration des routes
├── index.js             # Point d'entrée React
└── index.css            # Styles globaux
```

## Conventions

- **Composants** : Un fichier par composant, export par défaut
- **Utilitaires** : Fonctions pures exportées nommées
- **Constantes** : Valeurs statiques partagées
- **Pages** : Une page = une route dans App.js
