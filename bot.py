"""
CIAlert — bot.py
Bot Telegram ivoirien de détection d'arnaques.
Commandes : /start /aide /analyser /stats /signaler
"""

import asyncio
import logging
import os
import time
from typing import Optional

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

from agent import CIAlertAgent
from database import init_db, save_analysis, save_report, get_global_stats

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

load_dotenv()
logging.basicConfig(
    format="%(asctime)s · %(name)s · %(levelname)s · %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("CIAlert·Bot")

TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
agent = CIAlertAgent()

# États ConversationHandler
AWAIT_REPORT_TYPE, AWAIT_REPORT_PLATFORM, AWAIT_REPORT_AMOUNT, AWAIT_REPORT_DESC = range(4)

# Emojis risk
RISK_EMOJI = {
    "FAIBLE":   "🟢",
    "MOYEN":    "🟡",
    "ÉLEVÉ":    "🟠",
    "CRITIQUE": "🔴",
}

CAT_LABEL = {
    "broutage":     "Broutage / Romance scam",
    "mobile_money": "Arnaque Mobile Money",
    "phishing":     "Phishing / Faux site",
    "autre":        "Autre arnaque",
}


# ─────────────────────────────────────────────
# KEYBOARDS
# ─────────────────────────────────────────────

def main_keyboard():
    return ReplyKeyboardMarkup(
        [
            [KeyboardButton("🔍 Analyser un texte"), KeyboardButton("📊 Statistiques")],
            [KeyboardButton("⚠️ Signaler"),          KeyboardButton("❓ Aide")],
        ],
        resize_keyboard=True,
    )


def report_type_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("💰 Arnaque générale",    callback_data="rtype:arnaque")],
        [InlineKeyboardButton("📱 SMS frauduleux",       callback_data="rtype:sms_frauduleux")],
        [InlineKeyboardButton("🌐 Faux site web",        callback_data="rtype:faux_site")],
        [InlineKeyboardButton("❓ Autre",                callback_data="rtype:autre")],
    ])


def report_platform_keyboard():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("MTN MoMo",  callback_data="rplat:MTN"),
            InlineKeyboardButton("Orange Money", callback_data="rplat:Orange"),
        ],
        [
            InlineKeyboardButton("Wave",      callback_data="rplat:Wave"),
            InlineKeyboardButton("WhatsApp",  callback_data="rplat:WhatsApp"),
        ],
        [InlineKeyboardButton("⏭ Passer",    callback_data="rplat:skip")],
    ])


def result_keyboard(analysis_id: int):
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("⚠️ Signaler cette arnaque", callback_data=f"report_from:{analysis_id}")],
        [InlineKeyboardButton("🔍 Analyser autre chose",   callback_data="new_analysis")],
    ])


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def format_result(data: dict, analysis_id: int) -> str:
    """Formate le résultat d'analyse en message Telegram Markdown."""
    is_scam = data["is_scam"]
    risk    = data["risk_level"]
    emoji   = RISK_EMOJI.get(risk, "⚪")

    if is_scam:
        header = f"🚨 *ARNAQUE DÉTECTÉE* 🚨\n{emoji} Niveau de risque : *{risk}*"
    else:
        header = f"✅ *Contenu sain*\n🟢 Aucun signal d'arnaque détecté."

    conf_pct = round(data["confidence"] * 100)
    conf_bar = "█" * (conf_pct // 10) + "░" * (10 - conf_pct // 10)

    cat = CAT_LABEL.get(data.get("scam_category", ""), data.get("scam_category") or "—")

    flags = data.get("rule_flags", [])
    flags_txt = "\n".join(f"  • `{f}`" for f in flags) if flags else "  _Aucun_"

    explanation = data.get("explanation", "Aucune explication disponible.")

    ai_tag = f"🤖 _{data.get('ai_provider', 'règles').upper()}_" if data.get("ai_used") else "⚙️ _Règles locales_"

    return (
        f"{header}\n\n"
        f"📊 *Confiance :* {conf_pct}%\n"
        f"`{conf_bar}`\n\n"
        f"🏷 *Catégorie :* {cat}\n"
        f"⏱ *Traitement :* {data.get('processing_ms', '?')} ms\n"
        f"🧠 *Moteur :* {ai_tag}\n\n"
        f"📝 *Explication :*\n_{explanation}_\n\n"
        f"🚩 *Signaux détectés :*\n{flags_txt}\n\n"
        f"┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄\n"
        f"🆔 Analyse #{analysis_id}"
    )


# ─────────────────────────────────────────────
# COMMANDES DE BASE
# ─────────────────────────────────────────────

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    name = update.effective_user.first_name or "ami"
    await update.message.reply_text(
        f"🇨🇮 *Bienvenue sur CIAlert, {name} !*\n\n"
        "Je suis ton assistant anti-arnaques pour la Côte d'Ivoire.\n\n"
        "Envoie-moi directement un *SMS suspect*, un *lien douteux*, "
        "ou un *message WhatsApp* — je l'analyse en quelques secondes.\n\n"
        "Utilise le menu ci-dessous pour démarrer 👇",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=main_keyboard(),
    )


async def cmd_aide(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "❓ *Comment utiliser CIAlert ?*\n\n"
        "1️⃣ *Analyser* — envoie n'importe quel texte suspect directement\n"
        "2️⃣ */analyser* — lance l'analyse en mode texte libre\n"
        "3️⃣ */signaler* — signale une arnaque à la communauté\n"
        "4️⃣ */stats* — vois les chiffres de la plateforme\n\n"
        "💡 *Exemples de contenus à analyser :*\n"
        "• SMS : _«Vous avez gagné 500 000 FCFA…»_\n"
        "• Lien : `http://orange-money-bonus.tk`\n"
        "• Numéro : `+225 07 00 00 00`\n\n"
        "🔒 Tes messages sont analysés de façon anonyme.",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=main_keyboard(),
    )


async def cmd_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.chat.send_action(ChatAction.TYPING)
    try:
        s = get_global_stats()
        cats = s.get("categories", {})
        cats_txt = "\n".join(
            f"  • {CAT_LABEL.get(k, k)} : *{v}*"
            for k, v in sorted(cats.items(), key=lambda x: -x[1])
        ) or "  _Aucune donnée_"

        await update.message.reply_text(
            f"📊 *Statistiques CIAlert*\n\n"
            f"🔍 Analyses effectuées : *{s['total_analyses']}*\n"
            f"🚨 Arnaques détectées : *{s['total_scams']}*\n"
            f"📈 Taux d'arnaque : *{s['scam_rate']}%*\n"
            f"📝 Signalements reçus : *{s['total_reports']}*\n\n"
            f"🏷 *Par catégorie :*\n{cats_txt}",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=main_keyboard(),
        )
    except Exception as e:
        await update.message.reply_text(f"Erreur lors du chargement des stats : {e}")


# ─────────────────────────────────────────────
# ANALYSE DE TEXTE
# ─────────────────────────────────────────────

async def cmd_analyser(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Déclenché par /analyser ou le bouton 'Analyser un texte'."""
    await update.message.reply_text(
        "🔍 *Mode analyse activé*\n\nEnvoie le texte, lien ou numéro à vérifier :",
        parse_mode=ParseMode.MARKDOWN,
    )
    ctx.user_data["awaiting_analysis"] = True


async def handle_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Reçoit tout message texte et le soumet à l'agent."""
    text = update.message.text.strip()

    # Commandes clavier principal
    if text == "🔍 Analyser un texte":
        return await cmd_analyser(update, ctx)
    if text == "📊 Statistiques":
        return await cmd_stats(update, ctx)
    if text == "⚠️ Signaler":
        return await start_report(update, ctx)
    if text == "❓ Aide":
        return await cmd_aide(update, ctx)

    # Tout autre message → analyser directement
    await update.message.chat.send_action(ChatAction.TYPING)
    start = time.time()

    try:
        result = await agent.analyze(text=text, use_ai=True)
    except Exception as e:
        await update.message.reply_text(f"⚠️ Erreur d'analyse : {e}")
        return

    processing_ms = int((time.time() - start) * 1000)
    result["processing_ms"] = processing_ms

    analysis_id = save_analysis(
        input_text=text,
        is_scam=result["is_scam"],
        confidence=result["confidence"],
        risk_level=result["risk_level"],
        scam_category=result.get("scam_category"),
        rule_flags=result.get("rule_flags", []),
        ai_explanation=result.get("explanation"),
        ai_provider=result.get("ai_provider"),
        ai_used=result.get("ai_used", False),
        processing_ms=processing_ms,
        source="telegram",
    )

    ctx.user_data["last_analysis_id"] = analysis_id
    ctx.user_data["last_text"]        = text

    await update.message.reply_text(
        format_result(result, analysis_id),
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=result_keyboard(analysis_id),
    )


# ─────────────────────────────────────────────
# CONVERSATION : SIGNALEMENT
# ─────────────────────────────────────────────

async def start_report(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Démarre le flux de signalement manuel."""
    ctx.user_data.setdefault("report_data", {})
    ctx.user_data["report_data"]["text"] = ctx.user_data.get("last_text", "Signalement Telegram")
    ctx.user_data["report_data"]["analysis_id"] = ctx.user_data.get("last_analysis_id")

    msg = update.message or update.callback_query.message
    await msg.reply_text(
        "⚠️ *Signaler une arnaque*\n\nQuel type d'arnaque veux-tu signaler ?",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=report_type_keyboard(),
    )
    return AWAIT_REPORT_TYPE


async def report_type_chosen(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    rtype = query.data.split(":")[1]
    ctx.user_data["report_data"]["report_type"] = rtype

    await query.edit_message_text(
        f"✅ Type : *{rtype}*\n\nQuelle plateforme est concernée ?",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=report_platform_keyboard(),
    )
    return AWAIT_REPORT_PLATFORM


async def report_platform_chosen(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    platform = query.data.split(":")[1]
    ctx.user_data["report_data"]["platform"] = None if platform == "skip" else platform

    await query.edit_message_text(
        "💰 *Montant escroqué (FCFA)*\n\nTape le montant ou envoie `0` pour passer :",
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
        "📝 *Description*\n\nDécris brièvement ce qui s'est passé (ou envoie `/passer`) :",
        parse_mode=ParseMode.MARKDOWN,
    )
    return AWAIT_REPORT_DESC


async def report_desc_received(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    ctx.user_data["report_data"]["description"] = None if text.startswith("/passer") else text

    d = ctx.user_data["report_data"]
    report_id = save_report(
        reported_text=d.get("text", "—"),
        report_type=d.get("report_type", "autre"),
        analysis_id=d.get("analysis_id"),
        victim_amount=d.get("amount"),
        victim_platform=d.get("platform"),
        description=d.get("description"),
    )

    await update.message.reply_text(
        f"🙏 *Merci pour ton signalement !*\n\n"
        f"🆔 Référence : `#{report_id}`\n"
        "Ton signalement aide à protéger toute la communauté ivoirienne. 🇨🇮",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=main_keyboard(),
    )
    ctx.user_data["report_data"] = {}
    return ConversationHandler.END


async def report_cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Signalement annulé.", reply_markup=main_keyboard()
    )
    return ConversationHandler.END


# ─────────────────────────────────────────────
# CALLBACK QUERY (boutons inline)
# ─────────────────────────────────────────────

async def handle_callback(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data

    if data == "new_analysis":
        await query.message.reply_text(
            "🔍 Envoie le texte à analyser :", reply_markup=main_keyboard()
        )
    elif data.startswith("report_from:"):
        analysis_id = int(data.split(":")[1])
        ctx.user_data.setdefault("report_data", {})
        ctx.user_data["report_data"]["analysis_id"] = analysis_id
        ctx.user_data["report_data"]["text"] = ctx.user_data.get("last_text", "—")
        await query.message.reply_text(
            "⚠️ *Signaler une arnaque*\n\nQuel type ?",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=report_type_keyboard(),
        )


# ─────────────────────────────────────────────
# LANCEMENT
# ─────────────────────────────────────────────

def main():
    if not TELEGRAM_TOKEN:
        raise ValueError("TELEGRAM_BOT_TOKEN manquant dans .env !")

    init_db()

    app = Application.builder().token(TELEGRAM_TOKEN).build()

    # Conversation signalement
    report_conv = ConversationHandler(
        entry_points=[
            CommandHandler("signaler", start_report),
            # Le bouton "Signaler" du clavier principal est géré dans handle_text
        ],
        states={
            AWAIT_REPORT_TYPE:     [CallbackQueryHandler(report_type_chosen,     pattern="^rtype:")],
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
    app.add_handler(CommandHandler("analyser", cmd_analyser))
    app.add_handler(report_conv)
    app.add_handler(CallbackQueryHandler(handle_callback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    logger.info("🤖 CIAlert Bot démarré. En attente de messages…")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
