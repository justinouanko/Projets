# CIAlert

**Plateforme de détection d'arnaques digitales pour la Côte d'Ivoire**

CIAlert analyse messages, liens, numéros de téléphone et fichiers pour détecter les arnaques courantes en Côte d'Ivoire : fraude Mobile Money, broutage, phishing, faux emplois, fake news et bien d'autres.

Il suffit de coller un message ou déposer un fichier. CIAlert fait le reste.

> Projet récompensé au hackathon étudiant **SIADE 2026** 🇨🇮

---

## Démo

[cialert.up.railway.app](https://cialert.up.railway.app)

---

## Fonctionnalités

- **Détection automatique** — pas besoin de préciser le type de contenu
- **Analyse de fichiers** — PDF, images (PNG, JPG, WEBP), fichiers texte
- **Répertoire de numéros signalés** — consulté silencieusement à chaque analyse
- **Détection de fake news** — signaux de manipulation rhétorique et contextuelle
- **Signalement communautaire** — chaque signalement enrichit la base de données
- **Bot Telegram** — accès rapide depuis l'application de messagerie
- **IA swappable** — Groq (défaut), Gemini ou Claude via variable d'environnement

---

## Arnaques détectées

| Catégorie | Exemples |
|-----------|----------|
| Fraude Mobile Money | Faux gains MTN, Orange, Wave |
| Broutage | Arnaque romantique, escroquerie à distance |
| Phishing | Faux sites bancaires, faux portails |
| Faux emploi | Offres trop belles, avance de frais |
| Loterie fictive | "Vous avez gagné un iPhone..." |
| Arnaque crypto | Faux investissements, doublement de mise |
| Fake news | Désinformation, manipulation de l'opinion |
| SMS frauduleux | Messages d'urgence, usurpation d'identité |
| Faux support technique | Virus fictifs, accès à distance |

---

## Architecture

```
Utilisateur
    │
    ▼
Interface web (HTML/CSS/JS)
    │
    ▼
API FastAPI  ──────────────────────────────────────────┐
    │                                                  │
    ├── router.py         Détection du type d'input    │
    ├── agent.py          Moteur de détection (règles + IA)
    ├── file_extractor.py Extraction texte depuis fichiers
    ├── phone_registry.py Répertoire numéros signalés  │
    ├── response_builder.py Mise en forme des résultats│
    └── database.py       Couche données               │
                                                       │
PostgreSQL ─────────────────────────────────────────────┘
```

---

## Installation

### Prérequis

- Python 3.12+
- PostgreSQL
- Docker (recommandé pour Tesseract OCR)
- Un compte [Groq](https://console.groq.com) pour la clé API IA

### Variables d'environnement

Créez un fichier `.env` à la racine en vous basant sur `.env.example` :

```env
DATABASE_URL=postgresql://user:password@host:port/dbname
AI_PROVIDER=groq
GROQ_API_KEY=your_groq_api_key
GEMINI_API_KEY=your_gemini_api_key        # optionnel
ANTHROPIC_API_KEY=your_anthropic_api_key  # optionnel
VIRUSTOTAL_API_KEY=your_virustotal_api_key # optionnel
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
```

> Ne committez jamais votre fichier `.env`. Il est déjà dans `.gitignore`.

### Lancement avec Docker (recommandé)

```bash
git clone https://github.com/justinouanko/cialert.git
cd cialert
cp .env.example .env
# Remplissez les valeurs dans .env
docker build -t cialert .
docker run -p 8080:8080 --env-file .env cialert
```

### Lancement sans Docker

> Sans Docker, l'analyse d'images (OCR) ne sera pas disponible.

```bash
git clone https://github.com/justinouanko/cialert.git
cd cialert
cp .env.example .env
# Remplissez les valeurs dans .env
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8080
```

---

## Déploiement

CIAlert est conçu pour être déployé sur [Railway](https://railway.app).

1. Forkez le dépôt
2. Créez un projet Railway
3. Ajoutez un service PostgreSQL
4. Configurez les variables d'environnement
5. Railway détecte le `Dockerfile` et déploie automatiquement

---

## Contribuer

Les contributions sont les bienvenues, en particulier :

- Nouveaux patterns d'arnaques ivoiriennes
- Amélioration de la détection de numéros locaux
- Traductions (dioula, bété, autres langues locales)
- Corrections de bugs

**Avant de soumettre une PR :**
- Le code est en anglais, les commentaires en français
- Une fonction = un seul rôle
- Pas de données sensibles dans le code

---

## Stack technique

| Couche | Technologie |
|--------|-------------|
| Backend | FastAPI (Python 3.12) |
| Base de données | PostgreSQL |
| IA | Groq — Llama 3.1 8B |
| OCR | Tesseract + pdfplumber |
| Bot | python-telegram-bot |
| Déploiement | Railway |

---

## Contexte

CIAlert est né d'un constat simple : les outils de détection d'arnaques existants ne sont pas adaptés au contexte ivoirien. Les arnaques locales ont leurs propres codes, leurs propres plateformes et leurs propres cibles.

Ce projet vise à construire, avec la communauté, un outil qui comprend ce contexte — et qui reste accessible à tous, sans jargon technique.

---

*CIAlert — Fait en Côte d'Ivoire, pour la Côte d'Ivoire.*