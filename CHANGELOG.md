CIAlert — Changelog
V2.0.0 — 2026-04-20
Refonte majeure de l'architecture, de l'agent de détection et de l'interface publique.
🏗️ Architecture
Nouveau endpoint unifié POST /scan — remplace les anciens endpoints séparés /analyze et /fake-news. Accepte texte libre, URL, numéro de téléphone, fichier ou combinaison texte + fichier en un seul appel.
Router intelligent (router.py) — détecte automatiquement le type de contenu soumis (url, phone, sms, text) et orchestre les analyses nécessaires en parallèle via asyncio.gather.
response_builder.py — couche de transformation dédiée qui traduit les résultats techniques en réponse propre pour le frontend. Le frontend ne reçoit jamais de flags techniques, numéros extraits ou données brutes IA.
file_extractor.py — module d'extraction de texte depuis PDF (pdfplumber + OCR Tesseract fallback), images (OCR), et fichiers texte (UTF-8 / Latin-1 / CP1252). Limite : 10 Mo, troncature à 8 000 caractères.
Endpoints V1 (/analyze, /fake-news) maintenus en mode compatibilité pour le bot Telegram pendant la migration — marqués include_in_schema=False.
🤖 Agent de détection (agent.py V2.0)
Détection en 3 niveaux :
Règles locales étendues (patterns regex CI 2024-2025)
Threat intelligence : VirusTotal + Google Safe Browsing (optionnels, async)
IA avec prompt enrichi contexte ivoirien
9 catégories de scams couvertes : gain_improbable, demande_paiement, urgence, mobile_money, broutage, phishing, faux_emploi, crypto_invest, arnaque_admin
Broutage fortement enrichi — sextorsion, deepfake, usurpation de célébrité, pig butchering, arnaque colis douane, jeux en ligne, 30+ nouveaux patterns 2024-2025
Mobile Money enrichi — faux agents, syntaxes USSD piégées (*133*, *144*, *555*), réinitialisation de compte, SIM swap
Crypto/investissement enrichi — deepfakes TikTok/Instagram, fausses applis, rendements garantis 30-50%/mois
Bonus multi-catégories — score augmenté si plusieurs catégories déclenchées simultanément (combo broutage + paiement, broutage + urgence)
Label de confiance conditionnel :
is_scam=True → Probabilité d'arnaque (score brut)
is_scam=False → Fiabilité (score inversé : 1 - confidence)
📰 Détection Fake News (fake_news_agent.py — nouveau)
Nouveau module d'analyse rhétorique et contextuelle contre la désinformation
Analyse 3 familles de signaux : rhétoriques (alarmisme, urgence, appel au partage), contextuels (usurpation d'institutions CI : BCEAO, ARTCI, MTN, Orange…), sources (URLs imitant des médias connus)
Pré-analyse statique rapide avant appel IA
Verdicts : FIABLE / SUSPECT / MANIPULATOIRE avec score de manipulation 0-100
Activé automatiquement pour les URLs et les textes longs (≥ 300 caractères)
Utilise le même provider IA que l'agent principal (swappable via AI_PROVIDER)
📞 Répertoire de numéros suspects (phone_registry.py — nouveau)
Base de numéros ivoiriens signalés, alimentée automatiquement à chaque scan et signalement
Détection des formats : +225, 00225, 07/05/01 XXXXXXXX
Alerte frontend si un numéro du message analysé figure déjà dans le répertoire
🧠 Couche IA (ai_provider.py)
Provider swappable via variable d'environnement AI_PROVIDER : groq (défaut, gratuit), gemini, claude
Prompt système enrichi avec les techniques d'arnaque CI 2024-2025
Modèle Groq : llama-3.1-8b-instant (corrigé depuis llama3-8b-8192)
Fusion score règles / score IA pondérée : 35% règles + 65% IA
🗄️ Base de données
Migration SQLite → PostgreSQL (Railway) pour persistance des données en production
database.py avec détection automatique PostgreSQL vs SQLite et adaptation de syntaxe
Nouvelle table scans (endpoint /scan) en plus de l'ancienne table analyses (compatibilité V1)
Nouvelles tables : reports, feedback, phone_registry
Endpoint POST /feedback — boucle de retour utilisateur (✅ correct / ❌ incorrect) liée à chaque scan
🖥️ Frontend (index.html)
Refonte visuelle complète — thème beige chaud clair + dark mode #111110
Polices : Syne (titres) + DM Sans (corps)
Couleur accent : #FF5C1A (orange)
Toggle thème ☀️/🌙 persisté via localStorage
Zone de dépôt de fichier (drag & drop) — PDF, image, TXT
Section "Menaces Détectées" — filtrée MOYEN/ÉLEVÉ/CRITIQUE uniquement, top 3 visible + "voir plus" collapsible
Section "Signaler une Arnaque" — visible en permanence (plus de modal)
Boutons feedback ✅/❌ sur chaque résultat d'analyse
Label de confiance dynamique selon le verdict (Probabilité d'arnaque / Fiabilité)
🤖 Bot Telegram (bot.py V2.0)
Toutes les analyses passent désormais par POST /scan (plus d'appels directs à l'agent)
Support natif des photos (OCR) et documents (PDF, TXT)
Affichage du label de confiance conditionnel dans les résultats (conf_label depuis l'API)
Flux de signalement guidé via ConversationHandler (plateforme → montant → description)
Bouton inline "Signaler cette arnaque" directement depuis le résultat d'analyse
🐛 Corrections
Chemins statiques absolus (Path(__file__).parent / "static") pour éviter les 404 en déploiement
lifespan context manager remplace le déprécié on_event
Caractères typographiques français dans les strings JS échappés en Unicode pour éviter les crashs
confidence et scam_category désormais inclus dans la réponse API frontend (étaient absents en V1)
Score de fiabilité inversé (1 - confidence) quand le contenu est sain
V1.0.0 — 2025 (référence)
Endpoint /analyze texte uniquement
Agent de détection par règles locales + IA (Groq)
6 catégories de scams
Frontend simple, sans thème sombre
Base SQLite (Render) — perte de données entre redémarrages
Bot Telegram basique sans support fichier