# CIAlert : Détecteur d'arnaques digitales

> Plateforme ivoirienne de détection d'arnaques propulsée par l'IA.  
> Analyse SMS, liens, messages WhatsApp et numéros suspects en quelques secondes.

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-orange?style=flat-square)

---

## 🎯 Pourquoi CIAlert ?

En Côte d'Ivoire, les arnaques digitales explosent : broutage, faux Mobile Money (MTN, Orange, Wave), SMS frauduleux… Aucune plateforme IA accessible au grand public n'existait pour aider les citoyens.

CIAlert comble ce vide avec :
- Une **API REST** rapide (FastAPI + SQLite)
- Un **dashboard web** moderne et mobile-friendly
- Un **bot Telegram** pour analyser sans quitter son téléphone
- Une **IA interchangeable** (Groq gratuit par défaut, Gemini, Claude)

---

## 🏗️ Architecture

```
cialert/
├── main.py          # Backend FastAPI (API REST)
├── agent.py         # Cerveau de détection (règles + IA)
├── ai_provider.py   # Couche IA interchangeable
├── database.py      # SQLite : analyses, signalements, stats
├── bot.py           # Bot Telegram
├── static/
│   └── index.html   # Dashboard web
├── .env.example
└── requirements.txt
```

### Détection en 2 niveaux

```
Texte entrant
    │
    ▼
[Niveau 1] Règles locales (mots-clés, regex, patterns CI)
    │  → Résultat immédiat si confiance > seuil
    ▼
[Niveau 2] Analyse IA (Groq / Gemini / Claude)
    │  → Explication en français + catégorisation
    ▼
Verdict : SAIN | FAIBLE | MOYEN | ÉLEVÉ | CRITIQUE
```

---

## ⚡ Démarrage rapide

### 1. Cloner & installer

```bash
git clone https://github.com/justinouanko/Projets.git
cd Projets
pip install -r requirements.txt
```

### 2. Configurer

```bash
cp .env.example .env
# Édite .env et ajoute ta clé API
```

```env
# Choix de l'IA (une seule ligne à changer)
AI_PROVIDER=groq       # gratuit — recommandé pour démarrer
# AI_PROVIDER=gemini   # gratuit — alternative
# AI_PROVIDER=claude   # payant — meilleur

GROQ_API_KEY=gsk_...
# GEMINI_API_KEY=...
# CLAUDE_API_KEY=sk-ant-...

# Bot Telegram (optionnel)
TELEGRAM_BOT_TOKEN=...
```

### 3. Lancer l'API

```bash
python main.py
# → http://localhost:8000
# → http://localhost:8000/docs  (Swagger UI)
```

### 4. Lancer le bot Telegram (optionnel)

```bash
python bot.py
```

---

## 🔌 API

### `POST /analyze`

```json
{
  "text": "Félicitations ! Vous avez gagné 500 000 FCFA...",
  "input_type": "sms",
  "use_ai": true
}
```

**Réponse :**

```json
{
  "analysis_id": 42,
  "is_scam": true,
  "confidence": 0.94,
  "risk_level": "CRITIQUE",
  "scam_category": "mobile_money",
  "rule_flags": ["gain_improbable", "demande_paiement", "urgence"],
  "explanation": "Ce message présente tous les signes d'une arnaque Mobile Money...",
  "ai_used": true,
  "processing_ms": 312
}
```

### `POST /report`

```json
{
  "text": "Contenu signalé...",
  "report_type": "sms_frauduleux",
  "victim_platform": "MTN",
  "victim_amount": 50000,
  "description": "On m'a demandé d'envoyer de l'argent..."
}
```

### `GET /stats`

```json
{
  "total_analyses": 1247,
  "total_scams": 891,
  "scam_rate": 71.5,
  "total_reports": 134,
  "categories": {
    "mobile_money": 412,
    "broutage": 287,
    "phishing": 192
  }
}
```

---

## 🤖 Bot Telegram

| Commande | Action |
|---|---|
| `/start` | Message de bienvenue |
| `/analyser` | Mode analyse |
| `/signaler` | Signaler une arnaque (flux guidé) |
| `/stats` | Statistiques de la plateforme |
| `/aide` | Aide |
| _(tout message)_ | Analysé automatiquement |

---

## 🚀 Déploiement (gratuit)

### Render

```bash
# Dans Render : New Web Service → GitHub → cialert
# Build command : pip install -r requirements.txt
# Start command : uvicorn main:app --host 0.0.0.0 --port $PORT
```

### Railway

```bash
railway init
railway up
```

---

## 🗺️ Roadmap

- [x] Détection par règles locales
- [x] Couche IA interchangeable (Groq / Gemini / Claude)
- [x] API REST (FastAPI)
- [x] Base de données SQLite + stats
- [x] Dashboard web
- [x] Bot Telegram
- [x] Détection d'URLs malveillantes (VirusTotal API)
- [ ] Intégration WhatsApp Business API
- [ ] Application mobile Flutter
- [ ] Partenariat PLCC / ARTCI

---

## 🤝 Contribution

Pull requests bienvenues ! Pour les gros changements, ouvre d'abord une issue.

---

## 📄 Licence

MIT — Fait avec le ❤️ pour la Côte d'Ivoire
