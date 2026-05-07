from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .core import (
    CollectParams,
    HunterParams,
    SubnetRule,
    TokenEntry,
    DEFAULT_TARGET_NETWORKS,
    DEFAULT_TARGET_SUBNETS,
    required_zones,
)


@dataclass(frozen=True)
class AppConfig:
    tokens: list[TokenEntry]
    hunter: HunterParams
    collect: CollectParams
    target_subnets: list[SubnetRule]
    target_networks: list[ipaddress._BaseNetwork]
    allowed_chat_id: Optional[str]
    allowed_user_id: Optional[str]
    auto_spin_enabled: bool


@dataclass
class ToolStats:
    """Накопительная статистика поиска (обновляется по завершении прогона; сброс — кнопкой в боте)."""

    hunter_created: int = 0
    hunter_deleted: int = 0
    hunter_found: int = 0


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_tool_stats(data_dir: Path) -> ToolStats:
    p = data_dir / "stats.json"
    if not p.exists():
        return ToolStats()
    try:
        raw = _read_json(p)
        if not isinstance(raw, dict):
            return ToolStats()
        return ToolStats(
            hunter_created=int(raw.get("hunter_created", 0)),
            hunter_deleted=int(raw.get("hunter_deleted", 0)),
            hunter_found=int(raw.get("hunter_found", 0)),
        )
    except Exception:
        return ToolStats()


def save_tool_stats(data_dir: Path, s: ToolStats) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    p = data_dir / "stats.json"
    tmp = p.with_suffix(p.suffix + ".tmp")
    payload = {
        "hunter_created": s.hunter_created,
        "hunter_deleted": s.hunter_deleted,
        "hunter_found": s.hunter_found,
    }
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(p)


def dedupe_tokens(tokens: list[TokenEntry]) -> list[TokenEntry]:
    """
    Remove duplicates by token, keep first occurrence order.
    If later duplicates have missing label/proxy and earlier has them, we keep earlier.
    """
    seen: dict[str, TokenEntry] = {}
    order: list[str] = []
    for t in tokens:
        tok = (t.token or "").strip()
        if not tok:
            continue
        if tok not in seen:
            seen[tok] = TokenEntry(token=tok, label=(t.label or ""), proxy=t.proxy)
            order.append(tok)
            continue
        # merge minimal: prefer existing label/proxy, otherwise take from new
        cur = seen[tok]
        label = cur.label or (t.label or "")
        proxy = cur.proxy or t.proxy
        seen[tok] = TokenEntry(token=tok, label=label, proxy=proxy)
    return [seen[t] for t in order]


def load_tokens(accounts_path: Path) -> list[TokenEntry]:
    if not accounts_path.exists():
        return []
    raw = _read_json(accounts_path)
    if not isinstance(raw, list):
        raise ValueError("accounts.json must be a JSON array")
    out: list[TokenEntry] = []
    for item in raw:
        if not isinstance(item, dict) or not item.get("token"):
            continue
        out.append(TokenEntry(token=str(item["token"]), label=str(item.get("label", "")), proxy=item.get("proxy")))
    return dedupe_tokens(out)


def save_tokens(accounts_path: Path, tokens: list[TokenEntry]) -> None:
    accounts_path.parent.mkdir(parents=True, exist_ok=True)
    tokens = dedupe_tokens(tokens)
    payload = [
        {k: v for k, v in {"token": t.token, "label": t.label, "proxy": t.proxy}.items() if v}
        for t in tokens
    ]
    tmp = accounts_path.with_suffix(accounts_path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(accounts_path)


def save_config(config_path: Path, config: dict[str, Any]) -> None:
    config_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = config_path.with_suffix(config_path.suffix + ".tmp")
    tmp.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(config_path)


def patch_app_config(data_dir: Path, **updates: Any) -> None:
    """Merge keys into data/config.json (create file if missing)."""
    cfg_path = data_dir / "config.json"
    raw: dict[str, Any] = {}
    if cfg_path.exists():
        try:
            loaded = _read_json(cfg_path)
            if isinstance(loaded, dict):
                raw = loaded
        except Exception:
            raw = {}
    raw.update(updates)
    save_config(cfg_path, raw)


def load_app_config(
    data_dir: Path,
    env_bot_token: str,
    env_chat_id: str,
    env_admin_user_id: str,
) -> AppConfig:
    """
    Reads:
      - /data/accounts.json  (required)
      - /data/config.json    (optional)
    """
    accounts_path = data_dir / "accounts.json"
    cfg_path = data_dir / "config.json"

    tokens = load_tokens(accounts_path)

    # Defaults
    target_subnets = list(DEFAULT_TARGET_SUBNETS)
    target_networks = list(DEFAULT_TARGET_NETWORKS)
    hunter_dict: dict[str, Any] = {"zones": required_zones(target_subnets)}
    collect_dict: dict[str, Any] = {}
    allowed_chat_id: Optional[str] = env_chat_id or None
    allowed_user_id: Optional[str] = env_admin_user_id or None
    auto_spin_enabled = False

    if cfg_path.exists():
        raw = _read_json(cfg_path)
        if isinstance(raw, dict):
            auto_spin_enabled = bool(raw.get("auto_spin", False))
            if isinstance(raw.get("allowed_chat_id"), (str, int)):
                allowed_chat_id = str(raw["allowed_chat_id"])
            if isinstance(raw.get("allowed_user_id"), (str, int)):
                allowed_user_id = str(raw["allowed_user_id"])
            # networks/subnets override
            nets = raw.get("target_networks")
            subs = raw.get("target_subnets")
            if isinstance(subs, list) and subs:
                tmp: list[SubnetRule] = []
                for s in subs:
                    if not isinstance(s, dict):
                        continue
                    p = s.get("prefix")
                    z = s.get("zone")
                    l = s.get("loc")
                    if p and z and l:
                        tmp.append(SubnetRule(prefix=str(p), zone=str(z), loc=str(l)))
                if tmp:
                    target_subnets = tmp
            if isinstance(nets, list) and nets:
                tmpn: list[ipaddress._BaseNetwork] = []
                for n in nets:
                    try:
                        tmpn.append(ipaddress.ip_network(str(n)))
                    except Exception:
                        continue
                if tmpn:
                    target_networks = tmpn

            if isinstance(raw.get("hunter"), dict):
                hunter_dict.update(raw["hunter"])
            if isinstance(raw.get("collect"), dict):
                collect_dict.update(raw["collect"])

    # Ensure hunter.zones default uses current subnet zones if not explicitly set
    hunter_zones = hunter_dict.get("zones") or required_zones(target_subnets)
    if not isinstance(hunter_zones, list):
        hunter_zones = required_zones(target_subnets)

    hunter = HunterParams(
        zones=[str(z) for z in hunter_zones],
        delay_min=float(hunter_dict.get("delay_min", 1.0)),
        delay_max=float(hunter_dict.get("delay_max", 3.0)),
        create_delay_min=int(hunter_dict.get("create_delay_min", 3)),
        create_delay_max=int(hunter_dict.get("create_delay_max", 8)),
        pause_every=int(hunter_dict.get("pause_every", 20)),
        pause_duration_min=int(hunter_dict.get("pause_duration_min", 15)),
        pause_duration_max=int(hunter_dict.get("pause_duration_max", 30)),
        daily_limit=int(hunter_dict.get("daily_limit", 100)),
        stop_on_found=bool(hunter_dict.get("stop_on_found", False)),
    )

    collect = CollectParams(
        delay=float(collect_dict.get("delay", 0.3)),
        retries=int(collect_dict.get("retries", 3)),
        timeout=int(collect_dict.get("timeout", 30)),
        parallel=int(collect_dict.get("parallel", 5)),
        delete_nontarget=bool(collect_dict.get("delete_nontarget", True)),
    )

    return AppConfig(
        tokens=tokens,
        hunter=hunter,
        collect=collect,
        target_subnets=target_subnets,
        target_networks=target_networks,
        allowed_chat_id=allowed_chat_id,
        allowed_user_id=allowed_user_id,
        auto_spin_enabled=auto_spin_enabled,
    )

