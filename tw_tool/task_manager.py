from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Optional

from .config import ToolStats, load_tool_stats, save_tool_stats
from .core import (
    CollectParams,
    HunterParams,
    SubnetRule,
    TokenEntry,
    collect_run,
    hunter_events,
)


@dataclass
class RunStatus:
    hunter_running: bool = False
    collect_running: bool = False
    hunter_found: int = 0
    hunter_created: int = 0
    hunter_deleted: int = 0
    hunter_blacklisted: int = 0
    last_results_path: Optional[str] = None
    last_found: list[dict[str, Any]] = field(default_factory=list)
    recent_logs: list[str] = field(default_factory=list)

    def push_log(self, msg: str, limit: int = 60) -> None:
        self.recent_logs.append(msg)
        if len(self.recent_logs) > limit:
            self.recent_logs = self.recent_logs[-limit:]


class TaskManager:
    def __init__(
        self,
        data_dir: Path,
        tokens: list[TokenEntry],
        hunter_params: HunterParams,
        collect_params: CollectParams,
        target_subnets: list[SubnetRule],
        target_networks: list[Any],
        *,
        auto_spin_enabled: bool = False,
    ):
        self.data_dir = data_dir
        self.tokens = tokens
        self.hunter_params = hunter_params
        self.collect_params = collect_params
        self.target_subnets = target_subnets
        self.target_networks = target_networks
        self.auto_spin_enabled = bool(auto_spin_enabled)
        self.auto_spin_user_stopped = False

        self.status = RunStatus()

        self._hunter_task: Optional[asyncio.Task] = None
        self._collect_task: Optional[asyncio.Task] = None
        self._hunter_stop = asyncio.Event()
        self._collect_stop = asyncio.Event()

        self._queue: "asyncio.Queue[dict[str, Any]]" = asyncio.Queue()

        self.tool_stats: ToolStats = load_tool_stats(data_dir)

    def events(self) -> AsyncIterator[dict[str, Any]]:
        async def _gen():
            while True:
                ev = await self._queue.get()
                yield ev

        return _gen()

    def _emit(self, ev: dict[str, Any]) -> None:
        self._queue.put_nowait(ev)

    def stop_hunter(self) -> None:
        self._hunter_stop.set()

    def stop_collect(self) -> None:
        self._collect_stop.set()

    def stop_all(self) -> None:
        self.stop_hunter()
        self.stop_collect()

    def set_tokens(self, tokens: list[TokenEntry]) -> None:
        """
        Update tokens in runtime (used by bot token manager).
        Running tasks continue with the current token list reference; for safety,
        stop and restart tasks if you need strict consistency.
        """
        self.tokens = tokens

    def mark_auto_spin_user_stop(self) -> None:
        """User pressed Stop or /stop — do not auto-restart hunter until they start search manually or re-enable toggle."""
        self.auto_spin_user_stopped = True

    def clear_auto_spin_user_stop(self) -> None:
        self.auto_spin_user_stopped = False

    async def start_hunter(self) -> None:
        if not self.tokens:
            self._emit(
                {
                    "type": "log",
                    "level": "error",
                    "msg": "Нет токенов. Добавьте токены в разделе «Токены» в боте.",
                }
            )
            return
        if self._hunter_task and not self._hunter_task.done():
            return
        self._hunter_stop = asyncio.Event()
        self.status.hunter_running = True
        self._emit({"type": "log", "level": "info", "msg": "Поиск: старт"})

        async def _run():
            try:
                async for ev in hunter_events(
                    tokens=self.tokens,
                    params=self.hunter_params,
                    data_dir=self.data_dir,
                    target_subnets=self.target_subnets,
                    target_networks=self.target_networks,
                    stop_event=self._hunter_stop,
                ):
                    self._handle_event(ev)
                    self._emit(ev)
            finally:
                self.status.hunter_running = False
                self._emit({"type": "log", "level": "info", "msg": "Поиск: остановлен"})

        self._hunter_task = asyncio.create_task(_run())

    async def start_collect(self) -> None:
        if not self.tokens:
            self._emit(
                {
                    "type": "log",
                    "level": "error",
                    "msg": "Нет токенов. Добавьте токены в разделе «Токены» в боте.",
                }
            )
            return
        if self._collect_task and not self._collect_task.done():
            return
        self._collect_stop = asyncio.Event()
        self.status.collect_running = True
        self._emit({"type": "log", "level": "info", "msg": "Collect: старт"})

        async def _run():
            try:
                async for ev in collect_run(
                    tokens=self.tokens,
                    params=self.collect_params,
                    data_dir=self.data_dir,
                    target_networks=self.target_networks,
                    stop_event=self._collect_stop,
                ):
                    self._handle_event(ev)
                    self._emit(ev)
            finally:
                self.status.collect_running = False
                self._emit({"type": "log", "level": "info", "msg": "Collect: остановлен"})

        self._collect_task = asyncio.create_task(_run())

    def reset_tool_stats(self) -> None:
        self.tool_stats = ToolStats()
        save_tool_stats(self.data_dir, self.tool_stats)
        self.status.last_found.clear()
        self.status.recent_logs.clear()
        self.status.last_results_path = None

    def _handle_event(self, ev: dict[str, Any]) -> None:
        t = ev.get("type")
        if t == "log":
            msg = ev.get("msg", "")
            self.status.push_log(msg)
        elif t == "hunter_done":
            found = ev.get("found") or []
            self.tool_stats.hunter_created += int(ev.get("created", 0))
            self.tool_stats.hunter_deleted += int(ev.get("deleted", 0))
            self.tool_stats.hunter_found += len(found)
            save_tool_stats(self.data_dir, self.tool_stats)
        elif t == "done":
            self.status.last_results_path = ev.get("json_path") or self.status.last_results_path

