from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Optional

from telegram import BotCommand, InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.error import BadRequest
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ConversationHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from .config import dedupe_tokens, load_app_config, save_tokens
from .core import is_token_valid, normalize_token, required_zones
from .task_manager import TaskManager

logger = logging.getLogger("tw_tool")

STATE_ADD_ONE = 1
STATE_ADD_BULK = 2


def _kb_main(tm: TaskManager) -> InlineKeyboardMarkup:
    h = "⏹ Остановить" if tm.status.hunter_running else "Поиск IP"
    c = "⏹ Остановить" if tm.status.collect_running else "Проверка аккаунтов"
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    h,
                    callback_data="hunter_toggle",
                    style="primary" if tm.status.hunter_running else "success",
                ),
                InlineKeyboardButton(
                    c,
                    callback_data="collect_toggle",
                    style="primary" if tm.status.collect_running else "success",
                ),
            ],
            [
                InlineKeyboardButton("Статус", callback_data="status"),
                InlineKeyboardButton("Конфиг", callback_data="config"),
            ],
            [
                InlineKeyboardButton("🛠 Токены", callback_data="tokens"),
            ],
        ]
    )


def _allowed(update: Update, allowed_chat_id: Optional[str], allowed_user_id: Optional[str]) -> bool:
    # Admin-only mode (preferred): restrict by Telegram user id.
    if allowed_user_id:
        uid = str(update.effective_user.id) if update.effective_user else ""
        return uid == str(allowed_user_id)
    # Fallback: restrict by chat id if provided.
    if allowed_chat_id:
        chat_id = str(update.effective_chat.id) if update.effective_chat else ""
        return chat_id == str(allowed_chat_id)
    # No whitelist configured: allow only private chats.
    return bool(update.effective_chat and update.effective_chat.type == "private")


def _fmt_status(tm: TaskManager) -> str:
    s = tm.status
    hunter_state = "запущен" if s.hunter_running else "остановлен"
    collect_state = "запущен" if s.collect_running else "остановлен"
    text = (
        "<b>TW IP Tool · Статус</b>\n\n"
        f"Токенов: <code>{len(tm.tokens)}</code>\n"
        f"В чёрном списке: <code>{s.hunter_blacklisted}</code>\n\n"
        f"<b>Поиск (создание IP)</b>: <b>{hunter_state}</b>\n"
        f"Создано: <code>{s.hunter_created}</code>\n"
        f"Удалено (не подходит): <code>{s.hunter_deleted}</code>\n"
        f"Подходит (найдено): <code>{s.hunter_found}</code>\n\n"
        f"<b>Проверка аккаунтов</b>: <b>{collect_state}</b>\n"
        f"Подходит (найдено): <code>{s.collect_found}</code>\n"
        f"Удалено (лишние IP): <code>{s.collect_deleted}</code>\n"
    )
    return text


def _fmt_config(tm: TaskManager) -> str:
    subs = "\n".join(f"  • <code>{s.prefix}*</code> → {s.zone} ({s.loc})" for s in tm.target_subnets)
    return "<b>Target subnets:</b>\n" + subs


def _kb_tokens(tm: TaskManager) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("➕ Добавить 1", callback_data="tok_add_one", style="success")],
            [InlineKeyboardButton("➕ Добавить пачкой", callback_data="tok_add_bulk", style="success")],
            [InlineKeyboardButton("🔎 Проверка на дубли", callback_data="tok_dedupe", style="primary")],
            [InlineKeyboardButton("✅ Проверка правильности", callback_data="tok_validate", style="primary")],
            [InlineKeyboardButton("🧹 Удалить токены", callback_data="tok_clear", style="danger")],
            [InlineKeyboardButton("⬅ Назад", callback_data="back")],
        ]
    )

def _fmt_tokens(tm: TaskManager) -> str:
    return (
        "<b>Токены</b>\n\n"
        f"Сейчас: <code>{len(tm.tokens)}</code>\n\n"
        "Можно добавить 1 токен или пачкой (по одному на строку).\n"
        "Отмена ввода: /cancel"
    )


async def _send_text(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    text: str,
    reply_markup: InlineKeyboardMarkup | None = None,
    edit: bool = False,
) -> None:
    if update.callback_query and edit:
        try:
            await update.callback_query.edit_message_text(
                text=text, reply_markup=reply_markup, parse_mode=ParseMode.HTML
            )
        except BadRequest:
            # Message can't be edited (e.g. too old, deleted, not modified) — fallback to a new message.
            await update.effective_chat.send_message(
                text=text, reply_markup=reply_markup, parse_mode=ParseMode.HTML
            )
    else:
        await update.effective_chat.send_message(text=text, reply_markup=reply_markup, parse_mode=ParseMode.HTML)


class BotApp:
    def __init__(self, data_dir: Path, bot_token: str, env_chat_id: str):
        self.data_dir = data_dir
        self.bot_token = bot_token
        admin_uid = os.environ.get("TG_ADMIN_USER_ID", "").strip()
        cfg = load_app_config(
            data_dir,
            env_bot_token=bot_token,
            env_chat_id=env_chat_id,
            env_admin_user_id=admin_uid,
        )
        # If allowed_chat_id is set, we only accept commands from that chat.
        # Otherwise we accept only private chats (direct bot chat).
        self.allowed_chat_id = cfg.allowed_chat_id
        self.allowed_user_id = cfg.allowed_user_id
        self._active_chat_id: Optional[str] = None  # where to send logs if TG_CHAT_ID is not set
        if not cfg.tokens:
            logger.warning("No tokens loaded from %s", data_dir / "accounts.json")

        self.tm = TaskManager(
            data_dir=data_dir,
            tokens=cfg.tokens,
            hunter_params=cfg.hunter,
            collect_params=cfg.collect,
            target_subnets=cfg.target_subnets,
            target_networks=cfg.target_networks,
        )

        self._log_task: Optional[asyncio.Task] = None
        self._status_task: Optional[asyncio.Task] = None
        self._status_target: Optional[tuple[str, int]] = None  # (chat_id, message_id)

    def run(self) -> None:
        app = Application.builder().token(self.bot_token).build()

        app.add_handler(CommandHandler("start", self.cmd_start))
        app.add_handler(CommandHandler("status", self.cmd_status))
        app.add_handler(CommandHandler("stop", self.cmd_stop))

        conv = ConversationHandler(
            entry_points=[
                CallbackQueryHandler(self.cb_add_one, pattern="^tok_add_one$"),
                CallbackQueryHandler(self.cb_add_bulk, pattern="^tok_add_bulk$"),
            ],
            states={
                STATE_ADD_ONE: [MessageHandler(filters.TEXT & ~filters.COMMAND, self.msg_add_one)],
                STATE_ADD_BULK: [
                    MessageHandler(filters.Document.TEXT, self.doc_add_bulk),
                    MessageHandler(filters.TEXT & ~filters.COMMAND, self.msg_add_bulk),
                ],
            },
            fallbacks=[CommandHandler("cancel", self.cmd_cancel)],
            per_chat=True,
            per_user=True,
            per_message=False,
        )
        app.add_handler(conv)
        app.add_handler(CallbackQueryHandler(self.on_callback))
        app.add_error_handler(self.on_error)

        async def _post_init(_: Application):
            try:
                await app.bot.set_my_commands(
                    [
                        BotCommand("start", "Старт (показать меню)"),
                        BotCommand("status", "Статус"),
                        BotCommand("stop", "Остановить задачи"),
                        BotCommand("cancel", "Отмена ввода"),
                    ]
                )
            except Exception as e:
                logger.warning("Failed to set bot commands: %s", e)
            self._log_task = asyncio.create_task(self._log_loop(app))
            # status refresher runs on-demand (when user opens status)

        app.post_init = _post_init
        app.run_polling(allowed_updates=Update.ALL_TYPES)

    async def on_error(self, update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
        # Don't crash on Telegram edit/send errors; just log.
        logger.warning("Telegram handler error: %s", context.error)

    async def _log_loop(self, app: Application) -> None:
        """
        Consumes TaskManager events and sends log lines to chat in batches
        to avoid Telegram spam limits.
        """
        buf: list[str] = []
        last_flush = asyncio.get_event_loop().time()

        async for ev in self.tm.events():
            et = ev.get("type")
            if et == "admin_notice":
                await self._flush_logs(app, buf)
                buf.clear()
                await self._send_notice(app, ev)
                continue
            if et == "hunter_done":
                await self._flush_logs(app, buf)
                buf.clear()
                await self._send_summary(app, kind="hunter", payload=ev)
                continue
            if et == "done":
                # collect done
                await self._flush_logs(app, buf)
                buf.clear()
                await self._send_summary(app, kind="collect", payload=ev)
                continue
            if et != "log":
                continue
            msg = str(ev.get("msg", ""))
            level = ev.get("level", "info")
            # Чтобы не спамить: отправляем в чат только warn/error.
            if level not in ("warn", "error"):
                continue
            prefix = {"warn": "!", "error": "✗"}.get(level, "!")
            buf.append(f"{prefix} {msg}")

            now = asyncio.get_event_loop().time()
            if len(buf) >= 8 or (now - last_flush) >= 5.0:
                await self._flush_logs(app, buf)
                buf.clear()
                last_flush = now

    async def _send_notice(self, app: Application, ev: dict) -> None:
        chat_id = self.allowed_chat_id or self._active_chat_id
        if not chat_id:
            return
        kind = ev.get("kind", "")
        label = str(ev.get("label", ""))
        msg = str(ev.get("msg", ""))
        if kind == "no_balance":
            text = f"<b>Токен:</b> <code>{label}</code>\n{msg}"
        else:
            text = f"<b>Уведомление</b>\n<code>{label}</code>\n{msg}"
        try:
            await app.bot.send_message(chat_id=chat_id, text=text, parse_mode=ParseMode.HTML)
        except Exception as e:
            logger.warning("Failed to send notice: %s", e)

    async def _send_summary(self, app: Application, kind: str, payload: dict) -> None:
        chat_id = self.allowed_chat_id or self._active_chat_id
        if not chat_id:
            return
        try:
            if kind == "hunter":
                created = payload.get("created", 0)
                found = payload.get("found") or []
                lines = ["<b>Поиск завершен</b>", f"Создано: <code>{created}</code>", f"Подходит: <code>{len(found)}</code>"]
                if found:
                    lines.append("")
                    for r in found[:12]:
                        lines.append(f"• <code>{r.get('ip','')}</code> {r.get('loc','')} {r.get('zone','')} [{r.get('account','')}]")
                text = "\n".join(lines)
            else:
                total = payload.get("total", 0)
                found = payload.get("found", 0)
                deleted = payload.get("deleted", 0)
                text = "\n".join(
                    [
                        "<b>Проверка аккаунтов завершена</b>",
                        f"Аккаунтов: <code>{total}</code>",
                        f"Найдено: <code>{found}</code>",
                        f"Удалено лишних IP: <code>{deleted}</code>",
                    ]
                )
            await app.bot.send_message(chat_id=chat_id, text=text, parse_mode=ParseMode.HTML)
        except Exception as e:
            logger.warning("Failed to send summary: %s", e)

    async def _flush_logs(self, app: Application, lines: list[str]) -> None:
        if not lines:
            return
        chat_id = self.allowed_chat_id or self._active_chat_id
        if not chat_id:
            return
        try:
            text = "<b>Log</b>\n\n" + "\n".join(lines[-30:])
            await app.bot.send_message(chat_id=chat_id, text=text, parse_mode=ParseMode.HTML)
        except Exception as e:
            logger.warning("Failed to send logs: %s", e)

    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not _allowed(update, self.allowed_chat_id, self.allowed_user_id):
            return
        # remember chat for logs when TG_CHAT_ID isn't provided
        if update.effective_chat:
            self._active_chat_id = str(update.effective_chat.id)
        if not self.tm.tokens:
            await _send_text(
                update,
                context,
                "Токенов нет.\n\nДобавьте файл <code>/data/accounts.json</code> и перезапустите контейнер.",
                reply_markup=_kb_main(self.tm),
            )
            return
        await _send_text(update, context, "Панель управления:", reply_markup=_kb_main(self.tm))

    async def cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not _allowed(update, self.allowed_chat_id, self.allowed_user_id):
            return
        # Send a dedicated status message and refresh it every 5 seconds
        msg = await update.effective_chat.send_message(
            text=_fmt_status(self.tm), reply_markup=_kb_main(self.tm), parse_mode=ParseMode.HTML
        )
        self._active_chat_id = str(update.effective_chat.id)
        self._start_status_refresh(context.application, str(update.effective_chat.id), msg.message_id)

    async def cmd_stop(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not _allowed(update, self.allowed_chat_id, self.allowed_user_id):
            return
        self.tm.stop_all()
        await _send_text(update, context, "Останавливаю задачи…", reply_markup=_kb_main(self.tm))

    async def cmd_cancel(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        if not _allowed(update, self.allowed_chat_id, self.allowed_user_id):
            return ConversationHandler.END
        await _send_text(update, context, "Отменено.", reply_markup=_kb_main(self.tm))
        return ConversationHandler.END

    async def cb_add_one(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        q = update.callback_query
        if not q:
            return ConversationHandler.END
        await q.answer()
        if not _allowed(update, self.allowed_chat_id, self.allowed_user_id):
            return ConversationHandler.END
        await _send_text(
            update,
            context,
            "Пришлите <b>один</b> Timeweb Bearer токен (одной строкой).",
            reply_markup=None,
            edit=True,
        )
        return STATE_ADD_ONE

    async def cb_add_bulk(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        q = update.callback_query
        if not q:
            return ConversationHandler.END
        await q.answer()
        if not _allowed(update, self.allowed_chat_id, self.allowed_user_id):
            return ConversationHandler.END
        await _send_text(
            update,
            context,
            "Пришлите <b>TXT файл</b> с токенами (по одному на строку)\n"
            "или просто вставьте токены сообщением.\n"
            "Пустые строки и строки с <code>#</code> игнорируются.\n\n"
            "Отмена: /cancel",
            reply_markup=None,
            edit=True,
        )
        return STATE_ADD_BULK

    async def _add_bulk_from_lines(self, update: Update, context: ContextTypes.DEFAULT_TYPE, lines: list[str]) -> int:
        # Normalize + filter
        new = [normalize_token(l) for l in lines if normalize_token(l) and not normalize_token(l).startswith("#")]
        invalid = [t for t in new if not is_token_valid(t)]
        new = [t for t in new if is_token_valid(t)]
        if not new:
            await _send_text(update, context, "Не нашёл токенов. Пришли TXT или вставь токены, или /cancel")
            return STATE_ADD_BULK

        existing = {t.token for t in self.tm.tokens}
        # duplicates inside the pasted/file block
        dup_in_block = len(new) - len(set(new))
        # dedupe inside the block while preserving order
        seen_in_block: set[str] = set()
        add: list[str] = []
        for t in new:
            if t in existing or t in seen_in_block:
                continue
            seen_in_block.add(t)
            add.append(t)
        if not add:
            await _send_text(update, context, "Все эти токены уже добавлены.", reply_markup=_kb_main(self.tm))
            return ConversationHandler.END

        from .core import TokenEntry as TE

        tokens = list(self.tm.tokens)
        for t in add:
            tokens.append(TE(token=t, label=f"token_{len(tokens)+1}"))

        deduped = dedupe_tokens(tokens)
        removed_dups = len(tokens) - len(deduped)
        save_tokens(self.data_dir / "accounts.json", deduped)
        self.tm.set_tokens(deduped)

        msg_parts = [
            "Готово.\n\n",
            f"Добавлено новых: <code>{len(add)}</code>\n",
            f"Дублей в файле/вставке: <code>{dup_in_block}</code>\n",
            f"Удалено дублей при сохранении: <code>{removed_dups}</code>\n",
        ]
        if invalid:
            msg_parts.append(f"Пропущено некорректных: <code>{len(invalid)}</code>\n")
        msg_parts.append(f"Всего токенов: <code>{len(deduped)}</code>")

        await _send_text(update, context, "".join(msg_parts), reply_markup=_kb_main(self.tm))
        return ConversationHandler.END

    async def doc_add_bulk(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        if not _allowed(update, self.allowed_chat_id, self.allowed_user_id):
            return ConversationHandler.END
        if not update.message or not update.message.document:
            return STATE_ADD_BULK

        doc = update.message.document
        if not (doc.file_name or "").lower().endswith(".txt"):
            await _send_text(update, context, "Пришли именно <b>.txt</b> файл или /cancel")
            return STATE_ADD_BULK
        # basic size guard (Telegram allows large docs; we only need small txt)
        if doc.file_size and doc.file_size > 2_000_000:
            await _send_text(update, context, "Файл слишком большой. Пришли TXT до 2MB.")
            return STATE_ADD_BULK

        try:
            f = await context.bot.get_file(doc.file_id)
            data = await f.download_as_bytearray()
            text = bytes(data).decode("utf-8", errors="ignore")
            lines = text.splitlines()
        except Exception as e:
            await _send_text(update, context, f"Не удалось прочитать файл: {type(e).__name__}")
            return STATE_ADD_BULK

        return await self._add_bulk_from_lines(update, context, lines)

    async def msg_add_one(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        if not _allowed(update, self.allowed_chat_id, self.allowed_user_id):
            return ConversationHandler.END
        text = (update.message.text or "").strip() if update.message else ""
        if not text:
            await _send_text(update, context, "Пусто. Пришлите токен одной строкой или /cancel")
            return STATE_ADD_ONE

        tok = normalize_token(text)
        if not is_token_valid(tok):
            await _send_text(
                update,
                context,
                "Токен выглядит некорректно (есть пробелы/переносы строк).\n"
                "Пришли токен одной строкой без пробелов или /cancel",
            )
            return STATE_ADD_ONE
        if any(t.token == tok for t in self.tm.tokens):
            await _send_text(update, context, "Этот токен уже есть.", reply_markup=_kb_main(self.tm))
            return ConversationHandler.END

        from .core import TokenEntry as TE

        tokens = [*self.tm.tokens, TE(token=tok, label=f"token_{len(self.tm.tokens)+1}")]
        save_tokens(self.data_dir / "accounts.json", tokens)
        self.tm.set_tokens(tokens)
        await _send_text(update, context, f"Добавлено: <code>1</code>. Всего: <code>{len(tokens)}</code>", reply_markup=_kb_main(self.tm))
        return ConversationHandler.END

    async def msg_add_bulk(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        if not _allowed(update, self.allowed_chat_id, self.allowed_user_id):
            return ConversationHandler.END
        raw = (update.message.text or "") if update.message else ""
        return await self._add_bulk_from_lines(update, context, raw.splitlines())

    async def on_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        q = update.callback_query
        if not q:
            return
        await q.answer()
        if not _allowed(update, self.allowed_chat_id, self.allowed_user_id):
            return
        # remember chat for logs when TG_CHAT_ID isn't provided
        if update.effective_chat:
            self._active_chat_id = str(update.effective_chat.id)

        data = q.data or ""
        # Any navigation away from status stops auto-refresh.
        if data != "status":
            self._stop_status_refresh()
        if data == "tokens":
            await _send_text(update, context, _fmt_tokens(self.tm), reply_markup=_kb_tokens(self.tm), edit=True)
            return
        if data == "tok_dedupe":
            before = list(self.tm.tokens)
            after = dedupe_tokens(before)
            removed = len(before) - len(after)
            if removed > 0:
                save_tokens(self.data_dir / "accounts.json", after)
                self.tm.set_tokens(after)
                await _send_text(
                    update,
                    context,
                    "Проверка дублей завершена.\n\n"
                    f"Было токенов: <code>{len(before)}</code>\n"
                    f"Удалено дублей: <code>{removed}</code>\n"
                    f"Стало токенов: <code>{len(after)}</code>",
                    reply_markup=_kb_tokens(self.tm),
                    edit=True,
                )
            else:
                await _send_text(
                    update,
                    context,
                    "Проверка дублей завершена.\n\n"
                    "Дублей не найдено.\n"
                    f"Всего токенов: <code>{len(after)}</code>",
                    reply_markup=_kb_tokens(self.tm),
                    edit=True,
                )
            return
        if data == "tok_validate":
            before = list(self.tm.tokens)
            invalid = [t for t in before if not is_token_valid(t.token)]
            if not invalid:
                await _send_text(
                    update,
                    context,
                    "Проверка токенов завершена.\n\n"
                    f"Все токены корректные.\nВсего токенов: <code>{len(before)}</code>",
                    reply_markup=_kb_tokens(self.tm),
                    edit=True,
                )
                return

            # Remove invalid tokens automatically
            invalid_set = {t.token for t in invalid}
            after = [t for t in before if t.token not in invalid_set]
            save_tokens(self.data_dir / "accounts.json", after)
            self.tm.set_tokens(after)
            await _send_text(
                update,
                context,
                "Проверка токенов завершена.\n\n"
                f"Найдено некорректных: <code>{len(invalid)}</code>\n"
                f"Удалено некорректных: <code>{len(invalid)}</code>\n"
                f"Осталось токенов: <code>{len(after)}</code>",
                reply_markup=_kb_tokens(self.tm),
                edit=True,
            )
            return
        if data == "tok_clear":
            # Clear tokens on disk and in memory
            save_tokens(self.data_dir / "accounts.json", [])
            self.tm.set_tokens([])
            await _send_text(update, context, "Токены очищены.", reply_markup=_kb_main(self.tm), edit=True)
            return
        if data == "hunter_toggle":
            if self.tm.status.hunter_running:
                self.tm.stop_hunter()
                await _send_text(update, context, "Поиск: остановлен", reply_markup=_kb_main(self.tm), edit=True)
            else:
                if not self.tm.tokens:
                    await _send_text(
                        update,
                        context,
                        "Токенов нет. Добавьте <code>/data/accounts.json</code> и перезапустите контейнер.",
                        reply_markup=_kb_main(self.tm),
                        edit=True,
                    )
                    return
                await self.tm.start_hunter()
                await _send_text(update, context, "Поиск: запущен", reply_markup=_kb_main(self.tm), edit=True)
        elif data == "collect_toggle":
            if self.tm.status.collect_running:
                self.tm.stop_collect()
                await _send_text(update, context, "Проверка аккаунтов: остановлена", reply_markup=_kb_main(self.tm), edit=True)
            else:
                if not self.tm.tokens:
                    await _send_text(
                        update,
                        context,
                        "Токенов нет. Добавьте <code>/data/accounts.json</code> и перезапустите контейнер.",
                        reply_markup=_kb_main(self.tm),
                        edit=True,
                    )
                    return
                await self.tm.start_collect()
                await _send_text(update, context, "Проверка аккаунтов: запущена", reply_markup=_kb_main(self.tm), edit=True)
        elif data == "status":
            # Enable auto-refresh of this status message every 5 seconds.
            if update.effective_chat and update.callback_query and update.callback_query.message:
                self._start_status_refresh(
                    context.application,
                    str(update.effective_chat.id),
                    update.callback_query.message.message_id,
                )
            await _send_text(update, context, _fmt_status(self.tm), reply_markup=_kb_main(self.tm), edit=True)
        elif data == "back":
            await _send_text(update, context, "Панель управления:", reply_markup=_kb_main(self.tm), edit=True)
        elif data == "config":
            await _send_text(update, context, _fmt_config(self.tm), reply_markup=_kb_main(self.tm), edit=True)
        else:
            await _send_text(update, context, "Неизвестная команда", reply_markup=_kb_main(self.tm), edit=True)

    def _start_status_refresh(self, app: Application, chat_id: str, message_id: int) -> None:
        self._status_target = (chat_id, int(message_id))
        if self._status_task and not self._status_task.done():
            return

        async def _loop():
            # Refresh while target is set; stop after ~30 minutes to avoid runaway tasks
            for _ in range(30 * 60 // 5):
                if not self._status_target:
                    return
                c_id, m_id = self._status_target
                try:
                    await app.bot.edit_message_text(
                        chat_id=c_id,
                        message_id=m_id,
                        text=_fmt_status(self.tm),
                        reply_markup=_kb_main(self.tm),
                        parse_mode=ParseMode.HTML,
                    )
                except BadRequest:
                    # Can't edit anymore; stop refreshing.
                    self._status_target = None
                    return
                except Exception as e:
                    logger.warning("Status refresh failed: %s", e)
                await asyncio.sleep(5)

        self._status_task = asyncio.create_task(_loop())

    def _stop_status_refresh(self) -> None:
        self._status_target = None


def run_bot() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )
    bot_token = os.environ.get("TG_BOT_TOKEN", "").strip()
    if not bot_token:
        raise RuntimeError("TG_BOT_TOKEN is required")

    data_dir = Path(os.environ.get("DATA_DIR", "/data"))
    data_dir.mkdir(parents=True, exist_ok=True)

    # If you set TG_CHAT_ID, bot will only work in that chat and will send logs there.
    # If you don't set TG_CHAT_ID, bot will work in private chats and will send logs
    # to the chat where /start was used most recently.
    chat_id = os.environ.get("TG_CHAT_ID", "").strip()
    app = BotApp(data_dir=data_dir, bot_token=bot_token, env_chat_id=chat_id)
    app.run()

