from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import random
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, AsyncIterator, Optional

import httpx

logger = logging.getLogger("tw_tool")

API_BASE = "https://api.timeweb.cloud/api/v1"

_BEARER_RE = re.compile(r"(Bearer\s+)([A-Za-z0-9._\-]+)")


def _mask_secrets(s: str) -> str:
    if not s:
        return s
    return _BEARER_RE.sub(r"\1***", s)


def normalize_token(token: str) -> str:
    # Remove surrounding whitespace and quotes
    t = (token or "").strip().strip('"').strip("'").strip()
    return t


def is_token_valid(token: str) -> bool:
    t = normalize_token(token)
    if not t:
        return False
    # HTTP header values cannot contain control chars / whitespace
    return not any(ch.isspace() or ord(ch) < 32 for ch in t)


@dataclass(frozen=True)
class SubnetRule:
    prefix: str
    zone: str
    loc: str


DEFAULT_TARGET_SUBNETS: list[SubnetRule] = [
    SubnetRule("109.73.201.", "msk-1", "МСК"),
    SubnetRule("94.228.117.", "spb-3", "СПБ"),
    SubnetRule("81.200.148.", "spb-3", "СПБ"),
    SubnetRule("81.200.149.", "spb-3", "СПБ"),
    SubnetRule("81.200.150.", "spb-3", "СПБ"),
    SubnetRule("81.200.151.", "spb-3", "СПБ"),
]

DEFAULT_TARGET_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("109.73.201.0/24"),
    ipaddress.ip_network("94.228.117.0/24"),
    ipaddress.ip_network("81.200.148.0/24"),
    ipaddress.ip_network("81.200.149.0/24"),
    ipaddress.ip_network("81.200.150.0/24"),
    ipaddress.ip_network("81.200.151.0/24"),
]


def ip_in_targets(ip: str, target_networks: list[ipaddress._BaseNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in target_networks)
    except ValueError:
        return False


def check_subnet(ip: str, target_subnets: list[SubnetRule]) -> tuple[bool, str, str, str]:
    for rule in target_subnets:
        if ip.startswith(rule.prefix):
            return True, rule.prefix, rule.zone, rule.loc
    return False, "", "", ""


def required_zones(target_subnets: list[SubnetRule]) -> list[str]:
    return sorted({r.zone for r in target_subnets})


def make_client(token: str, proxy: Optional[str], timeout: int = 30) -> httpx.AsyncClient:
    transport = httpx.AsyncHTTPTransport(proxy=proxy) if proxy else None
    token = normalize_token(token)
    return httpx.AsyncClient(
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        transport=transport,
        timeout=timeout,
    )


async def create_ip(client: httpx.AsyncClient, zone: str) -> dict[str, Any]:
    try:
        r = await client.post(
            f"{API_BASE}/floating-ips",
            json={"availability_zone": zone, "is_ddos_guard": False},
        )
        if r.status_code == 201:
            return {"ok": True, "data": r.json()}
        return {"ok": False, "status": r.status_code, "body": r.text[:300]}
    except Exception as e:
        return {"ok": False, "status": 0, "body": _mask_secrets(f"{type(e).__name__}: {e}")}


async def delete_ip(client: httpx.AsyncClient, ip_id: int | str) -> tuple[bool, int | None, str]:
    try:
        r = await client.delete(f"{API_BASE}/floating-ips/{ip_id}")
        ok = r.status_code in (200, 204)
        return ok, r.status_code, (r.text or "")[:300]
    except Exception as e:
        return False, None, f"{type(e).__name__}: {e}"


async def list_ips(
    client: httpx.AsyncClient,
    *,
    retries: int = 3,
    base_delay: float = 1.0,
) -> list[dict[str, Any]]:
    """
    Fetch floating IPs with retries on temporary API errors (5xx/429).
    """
    for attempt in range(1, retries + 1):
        try:
            r = await client.get(f"{API_BASE}/floating-ips", params={"limit": 100, "offset": 0})
            if r.status_code == 200:
                return r.json().get("ips", [])
            if r.status_code in (429, 500, 502, 503, 504):
                await asyncio.sleep(base_delay * (2 ** (attempt - 1)))
                continue
            return []
        except Exception:
            await asyncio.sleep(base_delay * (2 ** (attempt - 1)))
    return []


@dataclass(frozen=True)
class TokenEntry:
    token: str
    label: str = ""
    proxy: Optional[str] = None


@dataclass(frozen=True)
class HunterParams:
    zones: list[str]
    delay_min: float = 1.0
    delay_max: float = 3.0
    create_delay_min: int = 3
    create_delay_max: int = 8
    pause_every: int = 20
    pause_duration_min: int = 15
    pause_duration_max: int = 30
    daily_limit: int = 100
    stop_on_found: bool = False


@dataclass(frozen=True)
class CollectParams:
    delay: float = 0.3
    retries: int = 3
    timeout: int = 30
    parallel: int = 5
    delete_nontarget: bool = True


@dataclass
class HunterState:
    found: dict[str, dict[str, Any]]
    created: int = 0
    blacklisted: int = 0


class TokenBlacklist:
    def __init__(self, path: Path):
        self.path = path
        self._data: dict[str, dict[str, str]] = {}
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                self._data = {}

    def _save(self):
        try:
            self.path.write_text(json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _cleanup(self):
        now = datetime.now()
        dead = []
        for k, v in list(self._data.items()):
            try:
                if datetime.fromisoformat(v["expires"]) < now:
                    dead.append(k)
            except Exception:
                dead.append(k)
        for k in dead:
            self._data.pop(k, None)
        if dead:
            self._save()

    def is_blacklisted(self, token: str) -> bool:
        self._cleanup()
        return token in self._data

    def add(self, token: str, reason: str, *, ttl_hours: float = 23.0):
        expires = (datetime.now() + timedelta(hours=float(ttl_hours))).isoformat()
        self._data[token] = {
            "reason": reason,
            "expires": expires,
            "added_at": datetime.now().isoformat(),
        }
        self._save()

    @property
    def entries(self) -> dict[str, dict[str, str]]:
        self._cleanup()
        return dict(self._data)


class IPBlacklist:
    def __init__(self, path: Path):
        self.path = path
        self._ips: set[str] = set()
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                self._ips = set(json.loads(self.path.read_text(encoding="utf-8")).get("ips", []))
            except Exception:
                self._ips = set()

    def _save(self):
        try:
            self.path.write_text(json.dumps({"ips": sorted(self._ips)}, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

    def add(self, ip: str):
        self._ips.add(ip)
        self._save()

    def has(self, ip: str) -> bool:
        return ip in self._ips


async def cleanup_nontarget_ips(
    client: httpx.AsyncClient,
    ip_bl: IPBlacklist,
    label: str,
    target_networks: list[ipaddress._BaseNetwork],
) -> AsyncIterator[dict[str, Any]]:
    ips = await list_ips(client)
    deleted = 0
    for item in ips:
        addr = item.get("ip", "")
        iid = item.get("id")
        if not addr or iid is None:
            continue
        if not ip_in_targets(addr, target_networks) and not ip_bl.has(addr):
            yield {"type": "log", "level": "info", "msg": f"[{label}] Удаляю нецелевой IP: {addr}"}
            ok, status, body = await delete_ip(client, iid)
            if ok:
                ip_bl.add(addr)
                deleted += 1
            else:
                yield {"type": "log", "level": "error", "msg": f"[{label}] Не удалилось {addr}: HTTP {status} {body}"}
            await asyncio.sleep(0.4)
    if deleted:
        yield {"type": "log", "level": "info", "msg": f"[{label}] Удалено нецелевых: {deleted}"}


async def hunter_events(
    tokens: list[TokenEntry],
    params: HunterParams,
    data_dir: Path,
    target_subnets: list[SubnetRule],
    target_networks: list[ipaddress._BaseNetwork],
    stop_event: asyncio.Event,
) -> AsyncIterator[dict[str, Any]]:
    token_bl = TokenBlacklist(data_dir / "blacklist.json")
    ip_bl = IPBlacklist(data_dir / "ip_blacklist.json")
    daily_cnt: dict[str, int] = defaultdict(int)
    daily_reset = datetime.now()

    found_subnets: dict[str, dict[str, Any]] = {}
    total_created = 0
    total_deleted = 0
    loop_n = 0
    malformed_cnt: dict[str, int] = {}
    target_prefixes = {r.prefix for r in target_subnets}

    rz = required_zones(target_subnets)
    zones_to_try = [z for z in params.zones if z in rz] or list(rz) or list(params.zones)

    yield {"type": "log", "level": "info", "msg": f"ПОИСК запущен. Токенов: {len(tokens)}, зон: {zones_to_try}"}
    yield {"type": "hunter_state", "found": 0, "created": 0, "blacklisted": 0}

    token_idx = 0
    while not stop_event.is_set():
        if datetime.now() - daily_reset > timedelta(days=1):
            daily_cnt.clear()
            daily_reset = datetime.now()

        available = [t for t in tokens if not token_bl.is_blacklisted(t.token)]
        if not available:
            yield {"type": "log", "level": "error", "msg": "Все токены исчерпаны!"}
            break

        tok = available[token_idx % len(available)]
        token_idx += 1
        tok_key = tok.token[:12] + "…"
        label = tok.label or tok_key

        if daily_cnt[tok.token] >= params.daily_limit:
            yield {"type": "log", "level": "warn", "msg": f"[{label}] Дневной лимит, blacklist"}
            token_bl.add(tok.token, "daily_limit")
            async with make_client(tok.token, tok.proxy) as cl:
                async for ev in cleanup_nontarget_ips(cl, ip_bl, label, target_networks):
                    yield ev
            continue

        loop_n += 1
        zone = zones_to_try[(loop_n - 1) % len(zones_to_try)]

        yield {"type": "log", "level": "info", "msg": f"[#{loop_n}] [{label}] Создаю IP → зона {zone}…"}

        await asyncio.sleep(random.uniform(params.delay_min, params.delay_max))
        if stop_event.is_set():
            break

        async with make_client(tok.token, tok.proxy) as cl:
            res = await create_ip(cl, zone)
            if res["ok"]:
                total_created += 1
                daily_cnt[tok.token] += 1
                ip_data = res["data"].get("ip", res["data"])
                addr = ip_data.get("ip", "")
                iid = ip_data.get("id")

                is_target = ip_in_targets(addr, target_networks)
                in_t, prefix, z_name, loc = check_subnet(addr, target_subnets)

                if is_target and in_t and prefix not in found_subnets:
                    found_subnets[prefix] = {
                        "ip": addr,
                        "prefix": prefix,
                        "zone": z_name,
                        "loc": loc,
                        "id": iid,
                        "account": label,
                        "found_at": datetime.now().isoformat(),
                    }
                    yield {"type": "log", "level": "ok", "msg": f"[{label}] ✅ НАЙДЕН {loc} IP: {addr} (prefix {prefix}*)"}
                    yield {
                        "type": "hunter_found",
                        "ip": addr,
                        "prefix": prefix,
                        "zone": z_name,
                        "loc": loc,
                        "account": label,
                        "id": iid,
                    }
                    if params.stop_on_found and len(found_subnets) >= len(target_prefixes):
                        yield {"type": "log", "level": "ok", "msg": "Все целевые подсети найдены, останавливаемся!"}
                        stop_event.set()
                elif not is_target:
                    yield {"type": "log", "level": "info", "msg": f"[{label}] ✗ Не подходит: {addr} — удаляю"}
                    if iid is not None:
                        await asyncio.sleep(0.4)
                        ok, status, body = await delete_ip(cl, iid)
                        if ok:
                            ip_bl.add(addr)
                            total_deleted += 1
                        else:
                            yield {"type": "log", "level": "error", "msg": f"[{label}] Не удалилось {addr}: HTTP {status} {body}"}
                elif in_t:
                    # Дубли в целевой подсети оставляем (по требованию).
                    yield {"type": "log", "level": "ok", "msg": f"[{label}] ✓ Подходит (дубль разрешён): {addr} ({prefix}*)"}
                else:
                    yield {"type": "log", "level": "ok", "msg": f"[{label}] ✓ Подходит (в target networks): {addr}"}
            else:
                status = res["status"]
                body = res["body"]
                # Timeweb может отдавать structured JSON:
                # {"error_code":"daily_limit_exceeded","details":{"available_date_for_creation":"..."}}
                if status in (400, 402, 403, 429):
                    try:
                        j = json.loads(str(body))
                        if isinstance(j, dict):
                            err = str(j.get("error_code", "")).lower()
                            if err == "daily_limit_exceeded":
                                dt_s = (
                                    (j.get("details") or {}).get("available_date_for_creation")
                                    if isinstance(j.get("details"), dict)
                                    else None
                                )
                                if isinstance(dt_s, str) and dt_s:
                                    try:
                                        # API gives ISO with timezone, python can parse it
                                        dt = datetime.fromisoformat(dt_s.replace("Z", "+00:00"))
                                        now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
                                        ttl_h = max(0.5, (dt - now).total_seconds() / 3600.0)
                                    except Exception:
                                        ttl_h = 23.0
                                else:
                                    ttl_h = 23.0
                                token_bl.add(tok.token, "daily_limit_exceeded", ttl_hours=ttl_h)
                                # Не спамим в чат такими событиями — это ожидаемая ситуация.
                                yield {"type": "log", "level": "info", "msg": f"[{label}] Дневной лимит → в blacklist"}
                                continue
                    except Exception:
                        pass

                # 5xx от Timeweb — чаще временные проблемы API, не спамим в чат (info).
                lvl = "info" if isinstance(status, int) and 500 <= status <= 599 else "error"
                yield {"type": "log", "level": lvl, "msg": f"[{label}] Ошибка {status}: {str(body)[:160]}"}

                body_l = str(body).lower()
                # Если на аккаунте нет денег или лимит создания IP исчерпан —
                # бессмысленно продолжать попытки: отправляем токен в blacklist на 23 часа.
                if status in (400, 402, 403) and (
                    "insufficient" in body_l
                    or "balance" in body_l
                    or "not enough" in body_l
                    or "недостат" in body_l
                    or "баланс" in body_l
                    or "лимит" in body_l
                    or "limit" in body_l
                    or "quota" in body_l
                ):
                    token_bl.add(tok.token, "no_balance_or_quota", ttl_hours=23)
                    yield {"type": "log", "level": "warn", "msg": f"[{label}] → blacklist на 23ч (баланс/лимит)"}
                    yield {
                        "type": "admin_notice",
                        "kind": "no_balance",
                        "label": label,
                        "msg": "На токене недостаточно средств (баланс/лимит).",
                    }
                    continue

                if status in (403, 429):
                    token_bl.add(tok.token, f"http_{status}")
                    yield {"type": "log", "level": "warn", "msg": f"[{label}] → blacklist (HTTP {status})"}
                    async with make_client(tok.token, tok.proxy) as cl2:
                        async for ev in cleanup_nontarget_ips(cl2, ip_bl, label, target_networks):
                            yield ev
                elif status == 0:
                    malformed_cnt[tok.token] = malformed_cnt.get(tok.token, 0) + 1
                    if malformed_cnt[tok.token] >= 2:
                        token_bl.add(tok.token, "malformed_reply")
                        yield {"type": "log", "level": "warn", "msg": f"[{label}] → blacklist (2x malformed reply)"}
                        malformed_cnt.pop(tok.token, None)
                else:
                    malformed_cnt.pop(tok.token, None)

        yield {
            "type": "hunter_state",
            "found": len(found_subnets),
            "created": total_created,
            "deleted": total_deleted,
            "blacklisted": sum(1 for t in tokens if token_bl.is_blacklisted(t.token)),
        }

        if loop_n % params.pause_every == 0:
            pause = random.randint(params.pause_duration_min, params.pause_duration_max)
            yield {"type": "log", "level": "info", "msg": f"--- Пауза {pause}с после {loop_n} итераций ---"}
            for _ in range(pause * 2):
                if stop_event.is_set():
                    break
                await asyncio.sleep(0.5)

        cd = random.randint(params.create_delay_min, params.create_delay_max)
        for _ in range(cd * 2):
            if stop_event.is_set():
                break
            await asyncio.sleep(0.5)

    yield {"type": "log", "level": "info", "msg": "Поиск остановлен."}
    yield {"type": "hunter_done", "found": list(found_subnets.values()), "created": total_created}


async def collect_run(
    tokens: list[TokenEntry],
    params: CollectParams,
    data_dir: Path,
    target_networks: list[ipaddress._BaseNetwork],
    stop_event: asyncio.Event,
) -> AsyncIterator[dict[str, Any]]:
    sem = asyncio.Semaphore(params.parallel)
    total = len(tokens)
    found = 0
    done_count = 0
    all_results: list[dict[str, Any]] = []
    deleted_total = 0

    yield {"type": "log", "level": "info", "msg": f"COLLECT запущен. Аккаунтов: {total}, параллельность: {params.parallel}"}

    async def fetch_one(tok: TokenEntry):
        async with sem:
            label = tok.label or (tok.token[:8] + "…")
            transport = httpx.AsyncHTTPTransport(proxy=tok.proxy) if tok.proxy else None
            async with httpx.AsyncClient(
                headers={"Authorization": f"Bearer {tok.token}", "Accept": "application/json"},
                transport=transport,
                timeout=params.timeout,
            ) as cl:
                limit, offset = 100, 0
                acc: list[dict[str, Any]] = []
                while True:
                    if stop_event.is_set():
                        break
                    r = None
                    for attempt in range(1, params.retries + 1):
                        try:
                            r = await cl.get(f"{API_BASE}/floating-ips", params={"limit": limit, "offset": offset})
                            if r.status_code == 200:
                                break
                            if r.status_code in (429, 500, 502, 503, 504):
                                await asyncio.sleep(2**attempt)
                                r = None
                        except httpx.RequestError:
                            await asyncio.sleep(2**attempt)

                    if r is None or r.status_code != 200:
                        raise RuntimeError("Нет ответа от API")

                    data = r.json()
                    items = data.get("ips", [])
                    total_meta = data.get("meta", {}).get("total", offset + len(items))

                    for item in items:
                        svc = item.get("service") or {}
                        acc.append(
                            {
                                "id": item.get("id", ""),
                                "ip": item.get("ip", ""),
                                "is_ddos_guard": item.get("is_ddos_guard", False),
                                "availability_zone": item.get("availability_zone", ""),
                                "service_id": svc.get("id"),
                                "service_type": svc.get("type"),
                                "created_at": item.get("created_at", ""),
                            }
                        )

                    offset += len(items)
                    if offset >= total_meta or not items:
                        break
                    await asyncio.sleep(params.delay)

                return tok, label, acc

    tasks = [asyncio.create_task(fetch_one(tok)) for tok in tokens]
    results_dir = data_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    for coro in asyncio.as_completed(tasks):
        if stop_event.is_set():
            break
        done_count += 1
        try:
            tok, label, ips = await coro
        except Exception as e:
            # Ошибка проверки одного аккаунта (после ретраев) — не спамим в чат.
            yield {"type": "log", "level": "info", "msg": f"[?] Ошибка проверки аккаунта: {e}"}
            yield {"type": "progress", "done": done_count, "total": total, "found": found}
            continue

        matched = [ip for ip in ips if ip_in_targets(ip.get("ip", ""), target_networks)]
        yield {"type": "log", "level": "info", "msg": f"[{label}] IP всего: {len(ips)}, в целевых: {len(matched)}"}

        if params.delete_nontarget:
            async with make_client(tok.token, tok.proxy) as cl:
                for ip in ips:
                    if stop_event.is_set():
                        break
                    addr = ip.get("ip", "")
                    iid = ip.get("id")
                    if not addr or not iid:
                        continue
                    if ip_in_targets(addr, target_networks):
                        continue
                    yield {"type": "log", "level": "info", "msg": f"[{label}] Удаляю лишний IP: {addr}"}
                    ok, status, body = await delete_ip(cl, iid)
                    if not ok:
                        yield {"type": "log", "level": "error", "msg": f"[{label}] Не удалось удалить {addr}: HTTP {status} {body}"}
                    else:
                        deleted_total += 1
                    await asyncio.sleep(max(0.2, params.delay))

        for ip in matched:
            rec = {**ip, "account_label": label}
            all_results.append(rec)
            found += 1
            yield {"type": "result", "ip": rec}

        yield {"type": "collect_state", "found": found, "deleted": deleted_total}
        yield {"type": "progress", "done": done_count, "total": total, "found": found}

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    jp = results_dir / f"collect_{ts}.json"
    jp.write_text(json.dumps(all_results, ensure_ascii=False, indent=2), encoding="utf-8")
    yield {"type": "done", "total": total, "found": found, "deleted": deleted_total, "json_path": str(jp)}

