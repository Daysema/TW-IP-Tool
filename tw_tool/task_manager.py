from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Optional

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
    collect_found: int = 0
    collect_deleted: int = 0
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
    ):
        self.data_dir = data_dir
        self.tokens = tokens
        self.hunter_params = hunter_params
        self.collect_params = collect_params
        self.target_subnets = target_subnets
        self.target_networks = target_networks

        self.status = RunStatus()

        self._hunter_task: Optional[asyncio.Task] = None
        self._collect_task: Optional[asyncio.Task] = None
        self._hunter_stop = asyncio.Event()
        self._collect_stop = asyncio.Event()

        self._queue: "asyncio.Queue[dict[str, Any]]" = asyncio.Queue()

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

    async def start_hunter(self) -> None:
        if not self.tokens:
            self._emit(
                {
                    "type": "log",
                    "level": "error",
                    "msg": "Нет токенов. Добавьте /data/accounts.json и перезапустите контейнер.",
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
                    "msg": "Нет токенов. Добавьте /data/accounts.json и перезапустите контейнер.",
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

    def _handle_event(self, ev: dict[str, Any]) -> None:
        t = ev.get("type")
        if t == "log":
            msg = ev.get("msg", "")
            self.status.push_log(msg)
        elif t == "hunter_state":
            self.status.hunter_found = int(ev.get("found", self.status.hunter_found))
            self.status.hunter_created = int(ev.get("created", self.status.hunter_created))
            self.status.hunter_deleted = int(ev.get("deleted", self.status.hunter_deleted))
            self.status.hunter_blacklisted = int(ev.get("blacklisted", self.status.hunter_blacklisted))
        elif t == "hunter_found":
            # keep small list of recent found
            self.status.last_found.insert(0, {k: ev.get(k) for k in ("ip", "prefix", "loc", "zone", "account")})
            self.status.last_found = self.status.last_found[:30]
        elif t == "collect_state":
            self.status.collect_found = int(ev.get("found", self.status.collect_found))
            self.status.collect_deleted = int(ev.get("deleted", self.status.collect_deleted))
        elif t == "done":
            self.status.last_results_path = ev.get("json_path") or self.status.last_results_path
            self.status.collect_found = int(ev.get("found", self.status.collect_found))
            self.status.collect_deleted = int(ev.get("deleted", self.status.collect_deleted))

