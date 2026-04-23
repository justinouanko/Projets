# 🛡️ CIAlert — Détecteur d'arnaques digitales 🇨🇮

> Plateforme open-source de détection d'arnaques et de désinformation,  
> conçue pour le contexte ivoirien et ouest-africain.

[![Version](https://img.shields.io/badge/version-2.1.0-orange)](https://github.com/justinouanko/cialert)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Railway](https://img.shields.io/badge/deployed-Railway-blueviolet)](https://cialert.up.railway.app)

---

## Pourquoi CIAlert ?

En Côte d'Ivoire, les arnaques digitales — broutage, faux Mobile Money, phishing, faux emplois — touchent des milliers de personnes chaque jour. CIAlert analyse en quelques secondes n'importe quel message, lien, numéro ou fichier suspect et retourne un verdict clair, en français, adapté au contexte local.

---

## Fonctionnalités V2.1.0

| Fonctionnalité | Description |
|---|---|
| 🔍 Détection multi-niveaux | Règles locales → Threat Intel → IA |
| 📰 Détection fake news | Analyse rhétorique et contextuelle |
| 📎 Analyse de fichiers | PDF, image (OCR), TXT jusqu'à 10 Mo |
| 📞 Répertoire de numéros | Alerte si numéro déjà signalé |
| 🤖 Bot Telegram | Analyse texte, photo, document |
| 💬 Bot WhatsApp | Analyse texte, image, PDF — flux signalement guidé |
| 🧾 Détecteur de faux reçus | Wave, MTN, Orange, Moov — OCR + analyse IA |
| 🔄 Feedback utilisateur | Boucle d'amélioration continue |
| 🌙 Dark mode | Interface claire/sombre persistée |
| 🔌 IA swappable | Groq / Gemini / Claude via `.env` |

---

## Architecture

```
cialert/
├── main.py              # API FastAPI — endpoints /scan /report /feedback /stats /history
├── router.py            # Orchestration des analyses en parallèle
├── agent.py             # Détection arnaque (règles + threat intel + IA)
├── fake_news_agent.py   # Détection désinformation
├── receipt_agent.py     # Détection faux reçus Mobile Money
├── ai_provider.py       # Couche IA swappable (Groq / Gemini / Claude)
├── file_extractor.py    # Extraction texte (PDF, image OCR, TXT)
├── phone_registry.py    # Répertoire numéros suspects
├── response_builder.py  # Construction réponse frontend
├── database.py          # PostgreSQL / SQLite auto-détecté
├── bot.py               # Bot Telegram V2.0
├── whatsapp_bot.py      # Bot WhatsApp (Meta Cloud API)
└── static/
    └── index.html       # Frontend
```

---

## Installation

### Prérequis

- Python 3.11+
- PostgreSQL (production) ou SQLite (développement local)
- Clé API Groq (gratuite) — ou Gemini / Claude

### Cloner et installer

```bash
git clone https://github.com/justinouanko/cialert.git
cd cialert
pip install -r requirements.txt
```

### Variables d'environnement

Crée un fichier `.env` à la racine :

```env
# IA — choisir un provider
AI_PROVIDER=groq          # groq | gemini | claude
GROQ_API_KEY=gsk_...
GROQ_MODEL=llama-3.1-8b-instant

# GEMINI (optionnel)
GEMINI_API_KEY=...
GEMINI_MODEL=gemini-1.5-flash

# CLAUDE (optionnel)
CLAUDE_API_KEY=sk-ant-...
CLAUDE_MODEL=claude-haiku-4-5-20251001

# Base de données
DATABASE_URL=postgresql://user:password@host:5432/cialert
# Laisser vide pour SQLite local

# Threat Intelligence (optionnel)
VIRUSTOTAL_API_KEY=...
GOOGLE_SAFE_BROWSING_KEY=...

# Bot Telegram (optionnel)
TELEGRAM_BOT_TOKEN=...
API_URL=https://cialert.up.railway.app

# Bot WhatsApp (optionnel)
WHATSAPP_TOKEN=...
WHATSAPP_PHONE_NUMBER_ID=...
WHATSAPP_VERIFY_TOKEN=...
```

### Lancer en local

```bash
# API
uvicorn main:app --reload --port 8000

# Bot Telegram (dans un autre terminal)
python bot.py

# Bot WhatsApp (dans un autre terminal)
python whatsapp_bot.py
```

L'interface est accessible sur `http://localhost:8000`.

---

## Endpoints API

| Méthode | Endpoint | Description |
|---|---|---|
| `POST` | `/scan` | Analyse universelle (texte, fichier, ou les deux) |
| `POST` | `/report` | Signalement manuel d'une arnaque |
| `POST` | `/feedback` | Retour utilisateur sur un résultat |
| `GET` | `/stats` | Statistiques globales |
| `GET` | `/history` | Historique des analyses |
| `GET` | `/health` | Santé de l'API |

### Exemple `/scan`

```bash
# Texte
curl -X POST https://cialert.up.railway.app/scan \
  -F "content=Félicitations ! Vous avez gagné 500 000 FCFA. Envoyez 5 000 F sur Orange Money."

# Fichier
curl -X POST https://cialert.up.railway.app/scan \
  -F "file=@capture.jpg"

# Texte + Fichier
curl -X POST https://cialert.up.railway.app/scan \
  -F "content=Voir le document ci-joint" \
  -F "file=@arnaque.pdf"
```

### Réponse type

```json
{
  "scan_id": 42,
  "is_scam": true,
  "confidence": 0.94,
  "confidence_label": "Probabilité d'arnaque",
  "risk_level": "CRITIQUE",
  "scam_category": "mobile_money",
  "message": "Ce message implique un transfert Mobile Money suspect.",
  "explanation": "Le message demande un envoi d'argent sous prétexte de débloquer un gain.",
  "advice": "Ne répondez pas, ne cliquez sur aucun lien et ne transférez aucun argent.",
  "receipt_warning": {
    "is_fake": true,
    "operateur": "Orange Money",
    "resume": "ID de transaction invalide, montant incohérent.",
    "recommandation": "Vérifiez ce reçu directement auprès de l'opérateur."
  },
  "processing_ms": 412
}
```

---

## Catégories détectées

| Catégorie | Description |
|---|---|
| `broutage` | Arnaque sentimentale, faux soldats ONU, sextorsion, pig butchering |
| `mobile_money` | Faux agents MTN/Orange/Wave, codes USSD piégés, SIM swap |
| `phishing` | Faux sites opérateurs, liens suspects, vol de credentials |
| `gain_improbable` | Fausse loterie, faux remboursement, faux bonus |
| `demande_paiement` | Frais de dossier, avance sur commission, frais de douane |
| `faux_emploi` | Recrutement urgent sans expérience, télétravail frauduleux |
| `crypto_invest` | Plateformes d'investissement garanties, doublement de mise |
| `arnaque_admin` | Faux visa, fausse bourse d'études, faux agents consulaires |
| `urgence` | Pression temporelle artificielle |

---

## Bot Telegram

Le bot analyse tout type de contenu directement depuis Telegram.

**Commandes disponibles :**
- Envoyer un texte → analyse immédiate
- Envoyer une photo → OCR + analyse
- Envoyer un PDF/TXT → extraction + analyse
- `/signaler` → flux guidé de signalement
- `/stats` → statistiques globales
- `/aide` → guide d'utilisation

👉 [@my_cialert_bot](https://t.me/my_cialert_bot)

---

## Bot WhatsApp

Le bot analyse texte, images et PDF directement depuis WhatsApp.

**Fonctionnalités :**
- Envoyer un message → analyse immédiate
- Envoyer une image ou un PDF → OCR + analyse
- Flux guidé de signalement en 4 étapes
- Menu interactif, statistiques, onboarding nouveaux utilisateurs
- Sessions conversationnelles persistées en PostgreSQL

👉 [wa.me/2250565366029](https://wa.me/2250565366029)

---

## Déploiement Railway

1. Forker le repo et connecter à Railway
2. Ajouter les variables d'environnement dans Railway → Variables
3. Railway détecte automatiquement FastAPI via `uvicorn`
4. Ajouter un service PostgreSQL Railway et copier `DATABASE_URL`

```bash
# Procfile (si nécessaire)
web: uvicorn main:app --host 0.0.0.0 --port $PORT
```

---

## Contribuer

Les contributions sont les bienvenues — en particulier :

- Nouveaux patterns d'arnaques ivoiriennes
- Amélioration du prompt IA
- Traduction en langues locales (dioula, baoulé...)
- Dataset labelisé de scams ivoiriens

```bash
git checkout -b feature/ma-contribution
git commit -m "feat: description"
git push origin feature/ma-contribution
```

---

## Licence

MIT — Libre d'utilisation, de modification et de distribution.

---

*Fait avec ❤️ à Abidjan, Côte d'Ivoire 🇨🇮*  
*Primé au SIADE 2026*
