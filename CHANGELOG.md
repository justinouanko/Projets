# Changelog — CIAlert

Toutes les versions notables de ce projet sont documentées ici.  
Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/).

---

## [2.1.0] — 2026-04-23

### Ajouté
- **Bot WhatsApp** — analyse texte, images (OCR) et PDF directement depuis WhatsApp
  - Flux de signalement guidé en 4 étapes
  - Menu interactif, statistiques, onboarding nouveaux utilisateurs
  - Sessions conversationnelles persistées en PostgreSQL
  - Intégration Meta Cloud API v19.0 — numéro +2250565366029
- **Détecteur de faux reçus Mobile Money** — nouveau module `receipt_agent.py`
  - Opérateurs couverts : Wave, MTN, Orange, Moov
  - Pipeline : nettoyage OCR → filtrage statique → extraction regex → analyse IA
  - Badge visuel "🧾 Faux reçu détecté" intégré dans le frontend
  - Résultat exposé via `receipt_warning` dans la réponse `/scan`

### Corrigé
- Faux positifs sur les reçus Orange Money (IDs de transaction avec points)
- `SyntaxError` sur regex backslash dans `receipt_agent.py` (crash Railway au démarrage)
- Prompt IA renforcé : neutralité accrue, suspicion uniquement sur preuve textuelle explicite

### Modifié
- `router.py` — intégration `receipt_agent` en parallèle dans le pipeline
- `response_builder.py` — construction du bloc `receipt_warning`
- `static/index.html` — badge faux reçu dans les résultats d'analyse

### Fichiers nouveaux
- `receipt_agent.py`
- `whatsapp_bot.py`

---

## [2.0.0] — 2026-01-XX

### Ajouté
- Endpoint unifié `/scan` avec orchestration parallèle asyncio
- Fusion règles (35%) + IA (65%) avec label confiance conditionnel
- Détection fake news — signaux rhétoriques ivoiriens
- Analyse de fichiers — PDF, image OCR, TXT
- Répertoire numéros suspects
- Feedback utilisateur ✅/❌ avec table PostgreSQL
- Bot Telegram V2 — texte, photo, document, flux signalement
- IA swappable — Groq / Gemini / Claude via `ai_provider.py`
- Migration SQLite → PostgreSQL Railway (persistance production)
- Interface Syne + DM Sans, accent #FF5C1A, dark mode

### Corrigé
- Perte de données à chaque redéploiement (SQLite sur Render → PostgreSQL sur Railway)
- Bug `save_fake_news_to_db` imbriqué dans `init_db()` (fonction isolée avec `get_connection()`)

---

## [1.0.0] — 2025-XX-XX

### Ajouté
- Version initiale — hackathon We.Code
- Détection basique arnaques textuelles
- 9 catégories de scams ivoiriens
- Patterns regex CI-spécifiques (+225, USSD, Mobile Money)
- Frontend vanilla HTML/CSS/JS
- Déploiement Render
