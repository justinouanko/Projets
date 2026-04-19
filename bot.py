"""
CIAlert — bot.py
Bot Telegram de détection d'arnaques — V2.0.
Toutes les analyses passent par POST /scan.
"""

import logging
import os
import time

import httpx
from dotenv import load_dotenv
from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    ReplyKeyboardMarkup,
    KeyboardButton,
)
from telegram.constants import ParseMode, ChatAction
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ConversationHandler,
    ContextTypes,
    filters,
)

from database import init_db, get_global_stats, save_report

load_dotenv()

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

logging.basicConfig(
    format="%(asctime)s · %(name)s · %(levelname)s · %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("CIAlert·Bot")

TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")

# URL de l'API — en local pointe vers localhost, en prod vers Railway
API_URL = os.getenv("API_URL", "http://localhost:8000")

# États du flux de signalement
AWAIT_REPORT_PLATFORM, AWAIT_REPORT_AMOUNT, AWAIT_REPORT_DESC = range(3)

# Emojis par niveau de risque
RISK_EMOJI = {
    "FAIBLE":   "🟢",
    "MOYEN":    "🟡",
    "ÉLEVÉ":    "🟠",
    "CRITIQUE": "🔴",
}


# ─────────────────────────────────────────────
# APPEL À L'API /scan
# ─────────────────────────────────────────────

async def call_scan(text: str) -> dict:
    """
    Envoie le texte à POST /scan et retourne le résultat.
    Lève une exception si l'API ne répond pas.
    """
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            f"{API_URL}/scan",
            data={"content": text},
        )
        response.raise_for_status()
        return response.json()


# ─────────────────────────────────────────────
# KEYBOARDS
# ─────────────────────────────────────────────

def main_keyboard():
    return ReplyKeyboardMarkup(
        [
            [KeyboardButton("🔍 Analyser"),    KeyboardButton("📊 Statistiques")],
            [KeyboardButton("⚠️ Signaler"),    KeyboardButton("❓ Aide")],
        ],
        resize_keyboard=True,
    )


def report_platform_keyboard():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("MTN MoMo",     callback_data="rplat:MTN"),
            InlineKeyboardButton("Orange Money",  callback_data="rplat:Orange"),
        ],
        [
            InlineKeyboardButton("Wave",          callback_data="rplat:Wave"),
            InlineKeyboardButton("WhatsApp",      callback_data="rplat:WhatsApp"),
        ],
        [InlineKeyboardButton("Passer",           callback_data="rplat:skip")],
    ])


def result_keyboard(scan_id: int):
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("⚠️ Signaler cette arnaque", callback_data=f"report_from:{scan_id}")],
        [InlineKeyboardButton("🔍 Analyser autre chose",   callback_data="new_analysis")],
    ])


# ─────────────────────────────────────────────
# FORMATAGE DU RÉSULTAT
# ─────────────────────────────────────────────

def format_result(data: dict) -> str:
    """
    Formate le résultat de /scan en message Telegram.
    Utilise les champs simplifiés du response_builder.
    """
    is_scam    = data.get("is_scam", False)
    risk_level = data.get("risk_level", "FAIBLE")
    emoji      = RISK_EMOJI.get(risk_level, "⚪")

    if is_scam:
        header = f"🚨 *Arnaque probable*\n{emoji} Niveau de risque : *{risk_level}*"
    else:
        header = "✅ *Contenu sain*\nAucun signal d'arnaque détecté."

    confidence = round((data.get("confidence") or 0) * 100)
    conf_bar   = "█" * (confidence // 10) + "░" * (10 - confidence // 10)

    # Message principal venant du response_builder
    message     = data.get("message", "")
    explanation = data.get("explanation", "")
    advice      = data.get("advice", "")

    # Avertissements supplémentaires
    extras = []
    if data.get("phone_warning"):
        extras.append(f"📵 _{data['phone_warning']}_")
    if data.get("fake_news") and data["fake_news"].get("verdict") != "FIABLE":
        extras.append(f"🔍 _{data['fake_news'].get('message', '')}_")

    extras_txt = "\n".join(extras)

    scan_id = data.get("scan_id", "—")

    lines = [
        header,
        "",
        f"📊 *Confiance :* {confidence}%",
        f"`{conf_bar}`",
        "",
    ]

    if message:
        lines += [f"💬 {message}", ""]

    if explanation:
        lines += [f"📝 _{explanation}_", ""]

    if advice:
        lines += [f"💡 *Que faire ?* {advice}", ""]

    if extras_txt:
        lines += [extras_txt, ""]

    lines.append(f"┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄")
    lines.append(f"🆔 Analyse #{scan_id}")

    return "\n".join(lines)


# ─────────────────────────────────────────────
# COMMANDES
# ─────────────────────────────────────────────

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    name = update.effective_user.first_name or "ami"
    await update.message.reply_text(
        f"🇨🇮 *Bienvenue sur CIAlert, {name} !*\n\n"
        "Je suis ton assistant anti-arnaques pour la Côte d'Ivoire.\n\n"
        "Envoie-moi directement un SMS suspect, un lien douteux "
        "ou un message WhatsApp — j'analyse tout automatiquement.\n\n"
        "Utilise le menu ci-dessous pour démarrer 👇",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=main_keyboard(),
    )


async def cmd_aide(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "❓ *Comment utiliser CIAlert ?*\n\n"
        "Envoie n'importe quel contenu suspect directement :\n"
        "• Un SMS : _«Vous avez gagné 500 000 FCFA…»_\n"
        "• Un lien : `http://orange-money-bonus.tk`\n"
        "• Un numéro : `+225 07 00 00 00`\n\n"
        "CIAlert détecte automatiquement le type et analyse.\n\n"
        "🔒 Tes messages sont analysés de façon anonyme.",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=main_keyboard(),
    )


async def cmd_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.chat.send_action(ChatAction.TYPING)
    try:
        s    = get_global_stats()
        cats = s.get("categories", {})
        cats_txt = "\n".join(
            f"  • {k} : {v}"
            for k, v in sorted(cats.items(), key=lambda x: -x[1])
        ) or "  Aucune donnée"

        await update.message.reply_text(
            f"📊 *Statistiques CIAlert*\n\n"
            f"🔍 Analyses : {s['total_analyses']}\n"
            f"🚨 Arnaques : {s['total_scams']}\n"
            f"📈 Taux : {s['scam_rate']}%\n"
            f"📝 Signalements : {s['total_reports']}\n\n"
            f"🏷 Par catégorie :\n{cats_txt}",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=main_keyboard(),
        )
    except Exception as error:
        logger.error(f"Erreur stats : {error}")
        await update.message.reply_text("Impossible de charger les statistiques.")


# ─────────────────────────────────────────────
# ANALYSE DE TEXTE
# ─────────────────────────────────────────────

async def handle_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Reçoit tout message texte et le soumet à /scan."""
    text = update.message.text.strip()

    # Boutons du clavier principal
    if text == "🔍 Analyser":
        await update.message.reply_text(
            "Envoie le texte, lien ou numéro à vérifier :",
            reply_markup=main_keyboard(),
        )
        return
    if text == "📊 Statistiques":
        return await cmd_stats(update, ctx)
    if text == "⚠️ Signaler":
        return await start_report(update, ctx)
    if text == "❓ Aide":
        return await cmd_aide(update, ctx)

    # Analyse via /scan
    await update.message.chat.send_action(ChatAction.TYPING)

    try:
        result = await call_scan(text)
    except httpx.HTTPStatusError as error:
        logger.error(f"Erreur API /scan : {error}")
        await update.message.reply_text(
            "L'analyse a échoué. Réessaye dans quelques instants."
        )
        return
    except Exception as error:
        logger.error(f"Erreur inattendue /scan : {error}")
        await update.message.reply_text("Une erreur s'est produite.")
        return

    # Sauvegarde du contexte pour le signalement éventuel
    ctx.user_data["last_scan_id"] = result.get("scan_id")
    ctx.user_data["last_text"]    = text

    scan_id = result.get("scan_id") or 0

    await update.message.reply_text(
        format_result(result),
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=result_keyboard(scan_id),
    )


# ─────────────────────────────────────────────
# FLUX DE SIGNALEMENT
# ─────────────────────────────────────────────

async def start_report(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Démarre le flux de signalement manuel."""
    ctx.user_data.setdefault("report_data", {})
    ctx.user_data["report_data"]["content"]  = ctx.user_data.get("last_text", "Signalement Telegram")
    ctx.user_data["report_data"]["scan_id"]  = ctx.user_data.get("last_scan_id")

    msg = update.message or update.callback_query.message
    await msg.reply_text(
        "⚠️ *Signaler une arnaque*\n\nQuelle plateforme est concernée ?",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=report_platform_keyboard(),
    )
    return AWAIT_REPORT_PLATFORM


async def report_platform_chosen(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query    = update.callback_query
    await query.answer()
    platform = query.data.split(":")[1]
    ctx.user_data["report_data"]["platform"] = None if platform == "skip" else platform

    await query.edit_message_text(
        "💰 Montant escroqué en FCFA (tape `0` pour passer) :",
        parse_mode=ParseMode.MARKDOWN,
    )
    return AWAIT_REPORT_AMOUNT


async def report_amount_received(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    try:
        amount = float(update.message.text.replace(" ", "").replace(",", "."))
        ctx.user_data["report_data"]["amount"] = amount if amount > 0 else None
    except ValueError:
        ctx.user_data["report_data"]["amount"] = None

    await update.message.reply_text(
        "📝 Décris brièvement ce qui s'est passé (ou envoie `/passer`) :",
        parse_mode=ParseMode.MARKDOWN,
    )
    return AWAIT_REPORT_DESC


async def report_desc_received(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    ctx.user_data["report_data"]["description"] = (
        None if text.startswith("/passer") else text
    )

    d = ctx.user_data["report_data"]

    try:
        report_id = save_report(
            reported_text=d.get("content", "—"),
            report_type="autre",        # détecté automatiquement côté DB
            scan_id=d.get("scan_id"),
            victim_amount=d.get("amount"),
            victim_platform=d.get("platform"),
            description=d.get("description"),
        )

        # Alimentation du répertoire de numéros
        from phone_registry import register_phone_from_text
        register_phone_from_text(
            text=d.get("content", ""),
            source="bot_report",
            report_id=report_id,
        )

        await update.message.reply_text(
            f"🙏 *Merci pour ton signalement !*\n\n"
            f"Référence : `#{report_id}`\n"
            "Ton signalement protège toute la communauté ivoirienne. 🇨🇮",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=main_keyboard(),
        )
    except Exception as error:
        logger.error(f"Erreur sauvegarde signalement : {error}")
        await update.message.reply_text(
            "Signalement non enregistré. Réessaye plus tard.",
            reply_markup=main_keyboard(),
        )

    ctx.user_data["report_data"] = {}
    return ConversationHandler.END


async def report_cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Signalement annulé.", reply_markup=main_keyboard())
    return ConversationHandler.END


# ─────────────────────────────────────────────
# CALLBACKS BOUTONS INLINE
# ─────────────────────────────────────────────

async def handle_callback(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data  = query.data

    if data == "new_analysis":
        await query.message.reply_text(
            "Envoie le texte à analyser :", reply_markup=main_keyboard()
        )
    elif data.startswith("report_from:"):
        scan_id = int(data.split(":")[1])
        ctx.user_data.setdefault("report_data", {})
        ctx.user_data["report_data"]["scan_id"]  = scan_id
        ctx.user_data["report_data"]["content"]  = ctx.user_data.get("last_text", "—")
        await query.message.reply_text(
            "⚠️ *Signaler une arnaque*\n\nQuelle plateforme est concernée ?",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=report_platform_keyboard(),
        )


# ─────────────────────────────────────────────
# LANCEMENT
# ─────────────────────────────────────────────

def main():
    if not TELEGRAM_TOKEN:
        raise ValueError("TELEGRAM_BOT_TOKEN manquant dans .env")

    init_db()

    app = Application.builder().token(TELEGRAM_TOKEN).build()

    # Flux de signalement
    report_conv = ConversationHandler(
        entry_points=[CommandHandler("signaler", start_report)],
        states={
            AWAIT_REPORT_PLATFORM: [CallbackQueryHandler(report_platform_chosen, pattern="^rplat:")],
            AWAIT_REPORT_AMOUNT:   [MessageHandler(filters.TEXT & ~filters.COMMAND, report_amount_received)],
            AWAIT_REPORT_DESC:     [MessageHandler(filters.TEXT, report_desc_received)],
        },
        fallbacks=[CommandHandler("annuler", report_cancel)],
        allow_reentry=True,
    )

    app.add_handler(CommandHandler("start",    cmd_start))
    app.add_handler(CommandHandler("aide",     cmd_aide))
    app.add_handler(CommandHandler("help",     cmd_aide))
    app.add_handler(CommandHandler("stats",    cmd_stats))
    app.add_handler(report_conv)
    app.add_handler(CallbackQueryHandler(handle_callback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    logger.info("CIAlert Bot V2.0 démarré.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()