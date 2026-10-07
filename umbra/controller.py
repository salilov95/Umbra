"""Application logic behind the HTTP API (no HTTP in here, easy to test)."""
from __future__ import annotations

import inspect
import json
import logging
import os
import socket
import ssl
import sys
import threading
import time
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

from . import UPDATE_REPO, __version__, autostart
from . import sysproxy as winproxy
from .core import CoreError, LogBuffer, XrayCore, free_port
from .links import ProxyLink, is_supported, parse_link
from .store import Store, new_id
from .subs import fetch_subscription
from .qr import make_qr
from .xrayconf import LOG_LEVELS, MODES, PRESETS, build_config, build_probe_config

log = logging.getLogger("umbra")

HEALTH_URL = "https://www.gstatic.com/generate_204"     # tiny page, used to probe the tunnel
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"   # tells which IP the world sees
# Some hosts (Cloudflare among them) answer 403 to Python's default User-Agent.
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
# Speed test payloads, tried in this order until one answers.
SPEED_URLS = [
    "https://speed.cloudflare.com/__down?bytes=25000000",
    "https://proof.ovh.net/files/100Mb.dat",
    "https://fsn1-speed.hetzner.com/100MB.bin",
    "http://cachefly.cachefly.net/100mb.test",
]
SPEED_SECONDS = 8           # the speed test stops after this long
SITE_TIMEOUT = 7            # per-path limit of the "is this site reachable" check
EXPIRY_WARN_DAYS = 5        # warn when a subscription ends this soon
UPDATE_URL = "https://github.com/{repo}/releases/latest"   # redirects to .../tag/vX.Y.Z
PROBE_TIMEOUT = 8           # per-server limit when measuring delay through the tunnel
THEMES = ("dark", "light")
ACCENTS = ("teal", "sky", "lavender", "mint", "lime")
HEALTH_INTERVAL = 20        # seconds between tunnel probes
HEALTH_FAILS = 3            # failed probes in a row = "tunnel is down"
RECONNECT_DELAYS = (1, 3, 6)
FAILOVER_COOLDOWN = 60
SUB_MAX_AGE = 12 * 3600
HISTORY = 60                # seconds of speed history kept for the chart

BOOL_SETTINGS = ("sysproxy", "show_connections", "auto_connect", "auto_reconnect",
                 "failover", "sub_auto_update", "close_to_tray", "notifications")
RESTART_KEYS = ("socks_port", "http_port", "loglevel", "direct_domains", "proxy_domains",
                "show_connections", "presets")


class ApiError(Exception):
    """Error whose text is shown to the user as is."""


def tcp_ping(host: str, port: int, timeout: float = 3.0) -> int:
    """Time of a TCP handshake in ms, or -1. This is reachability, not speed."""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except OSError:
        return -1
    return max(1, int((time.perf_counter() - start) * 1000))


def parse_version(text: str) -> tuple[int, ...]:
    """'v0.5.1' or '.../tag/0.5.1' -> (0, 5, 1). Empty tuple when there is no version."""
    tail = text.rstrip("/").rsplit("/", 1)[-1].lstrip("vV")
    parts = []
    for piece in tail.split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


def make_opener(proxy: str | None) -> urllib.request.OpenerDirector:
    """proxy=None: straight to the internet, ignoring any system proxy."""
    handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {})
    opener = urllib.request.build_opener(handler)
    opener.addheaders = [("User-Agent", USER_AGENT)]
    return opener


def explain_error(exc: BaseException) -> str:
    """Turn a network exception into words a user understands."""
    reason = getattr(exc, "reason", exc)
    if isinstance(reason, socket.gaierror):
        return "адрес не найден (DNS)"
    if isinstance(reason, (TimeoutError, socket.timeout)) or "timed out" in str(reason):
        return "нет ответа, время вышло"
    if isinstance(reason, ConnectionResetError):
        return "соединение сброшено"
    if isinstance(reason, ConnectionRefusedError):
        return "в соединении отказано"
    text = str(reason)
    if "Tunnel connection failed" in text:
        return "сервер не смог связаться с сайтом"
    if isinstance(reason, ssl.SSLError):
        if "EOF" in text:
            return "соединение оборвано"
        return "ошибка защищённого соединения (TLS)"
    return str(reason)[:120] or type(exc).__name__


def probe_url(url: str, proxy: str | None, timeout: float = SITE_TIMEOUT) -> dict:
    """One GET. Any HTTP answer (even 403 or 404) means the site is reachable."""
    start = time.perf_counter()
    try:
        with make_opener(proxy).open(url, timeout=timeout) as r:
            r.read(1)
            status = r.status
    except HTTPError as exc:
        status = exc.code                       # the site answered: reachable
        if proxy and url.startswith("http://") and status in (502, 503, 504):
            # For plain http the local proxy itself answers with a gateway
            # error when the far end is unreachable; that is not the site talking.
            return {"ok": False, "status": None, "ms": None,
                    "error": "сервер не смог связаться с сайтом"}
    except (URLError, OSError, ValueError) as exc:
        return {"ok": False, "status": None, "ms": None, "error": explain_error(exc)}
    return {"ok": True, "status": status, "error": None,
            "ms": max(1, int((time.perf_counter() - start) * 1000))}


def split_flag(name: str) -> tuple[str, str]:
    """'🇳🇱 Name' -> ('NL', 'Name'). Windows has no flag glyphs, so the UI draws the code."""
    if len(name) >= 2 and all(0x1F1E6 <= ord(c) <= 0x1F1FF for c in name[:2]):
        code = "".join(chr(ord(c) - 0x1F1E6 + ord("A")) for c in name[:2])
        return code, name[2:].strip() or code
    return "", name


def clean_list(value, limit: int = 500) -> list[str]:
    if not isinstance(value, list):
        raise ApiError("ожидался список строк")
    return [str(x).strip()[:253] for x in value if str(x).strip()][:limit]


class Traffic:
    """Turns Xray's ever-growing byte counters into speed + a short history."""

    def __init__(self):
        self.reset()

    def reset(self) -> None:
        self.last: tuple[float, int, int] | None = None
        self.down_bps = self.up_bps = 0
        self.down_total = self.up_total = 0
        self.proxy_total = self.direct_total = 0
        self.history: deque = deque([[0, 0]] * HISTORY, maxlen=HISTORY)

    def update(self, stats: dict, now: float) -> None:
        inbound = stats.get("inbound") or {}
        down = sum(int(v.get("downlink", 0)) for v in inbound.values())
        up = sum(int(v.get("uplink", 0)) for v in inbound.values())
        outbound = stats.get("outbound") or {}

        def both(tag: str) -> int:
            o = outbound.get(tag) or {}
            return int(o.get("downlink", 0)) + int(o.get("uplink", 0))

        self.proxy_total, self.direct_total = both("proxy"), both("direct")
        if self.last:
            t, d0, u0 = self.last
            dt = now - t
            if dt > 0:
                self.down_bps = max(0, int((down - d0) / dt))
                self.up_bps = max(0, int((up - u0) / dt))
        self.last = (now, down, up)
        self.down_total, self.up_total = down, up
        self.history.append([self.down_bps, self.up_bps])

    def public(self) -> dict:
        return {
            "down_bps": self.down_bps, "up_bps": self.up_bps,
            "down_total": self.down_total, "up_total": self.up_total,
            "proxy_total": self.proxy_total, "direct_total": self.direct_total,
            "history": list(self.history),
        }


class Controller:
    def __init__(self, home: Path):
        self.home = home
        self.store = Store(home)
        self.logs = LogBuffer()
        self.core = XrayCore(home, self.logs)
        self.lock = threading.RLock()
        self.connected = False
        self.connecting = False
        self.reconnecting = False
        self.connected_at: float | None = None
        self.pings: dict[str, int] = {}      # TCP handshake, ms (-1 = no answer)
        self.delays: dict[str, int] = {}     # request through the tunnel, ms (-1 = tunnel broken)
        self.speed: dict | None = None       # last speed test of the active server
        self.traffic = Traffic()
        self.health: dict = {"ms": None, "fails": 0, "checked_at": None}
        self.exit: dict | None = None
        self.metrics_port: int | None = None
        self.quit_event = threading.Event()
        self.tray_active = False      # set by app.py when the tray icon is up
        self.notify_hook = None       # app.py puts tray.balloon here
        self.update: dict | None = None   # {"version", "url"} when a newer release exists
        self._expiry_warned: set[str] = set()
        self.last_seen = time.time()
        self._gen = 0                 # grows on every connect/disconnect
        self._cancel_reconnect = False
        self._next_health = 0.0
        self._want_exit = False
        self._last_failover = 0.0
        threading.Thread(target=self._ticker, daemon=True).start()
        threading.Thread(target=self._health_loop, daemon=True).start()

    # ---- helpers ------------------------------------------------------
    def say(self, text: str) -> None:
        self.logs.add("app", text)
        log.info(text)

    def notify(self, title: str, text: str) -> None:
        """Journal line + a tray balloon (if there is a tray and the user wants them)."""
        self.say(f"{title}: {text}")
        hook = self.notify_hook
        if hook and self.data["notifications"]:
            try:
                hook(title, text)
            except Exception:  # noqa: BLE001 - a notification must never break the work
                log.exception("notify")

    @property
    def data(self) -> dict:
        return self.store.data

    def _find(self, sid: str) -> dict:
        for s in self.data["servers"]:
            if s["id"] == sid:
                return s
        raise ApiError("сервер не найден")

    def _find_sub(self, sub_id: str) -> dict:
        for s in self.data["subscriptions"]:
            if s["id"] == sub_id:
                return s
        raise ApiError("подписка не найдена")

    @staticmethod
    def _parse(link: str) -> ProxyLink:
        try:
            return parse_link(link)
        except ValueError as exc:
            raise ApiError(str(exc)) from exc

    def _public_server(self, s: dict) -> dict:
        country, title = split_flag(s["name"])
        item = {"id": s["id"], "name": title, "country": country, "sub": s.get("sub"),
                "ping": self.pings.get(s["id"]), "delay": self.delays.get(s["id"]), "error": None}
        try:
            item.update(parse_link(s["link"]).public_info())
        except ValueError as exc:
            item["error"] = str(exc)
        return item

    def _public_sub(self, sub: dict) -> dict:
        # The URL itself holds an access token, so only the host goes to the UI.
        return {
            "id": sub["id"],
            "name": sub.get("name") or urlsplit(sub["url"]).hostname or "подписка",
            "host": urlsplit(sub["url"]).hostname or "",
            "updated_at": sub.get("updated_at"),
            "info": sub.get("info") or {},
            "count": sum(1 for s in self.data["servers"] if s.get("sub") == sub["id"]),
        }

    # ---- state / polling ---------------------------------------------
    def state(self) -> dict:
        d = self.data
        with self.lock:
            return {
                "version": __version__,
                "platform": sys.platform,
                "servers": [self._public_server(s) for s in d["servers"]],
                "subs": [self._public_sub(s) for s in d["subscriptions"]],
                "selected": d["selected"],
                "mode": d["mode"],
                "modes": MODES,
                "connected": self.connected,
                "connecting": self.connecting,
                "reconnecting": self.reconnecting,
                "connected_at": self.connected_at,
                "proxy_active": d["proxy_active"],
                "traffic": self.traffic.public(),
                "health": dict(self.health),
                "exit": self.exit,
                "speed": self.speed,
                "tray": self.tray_active,
                "update": self.update,
                "presets": {k: v["title"] for k, v in PRESETS.items()},
                "settings": {
                    **{k: d[k] for k in BOOL_SETTINGS},
                    "socks_port": d["socks_port"],
                    "http_port": d["http_port"],
                    "loglevel": d["loglevel"],
                    "direct_domains": d["direct_domains"],
                    "proxy_domains": d["proxy_domains"],
                    "presets": d["presets"],
                    "theme": d["theme"],
                    "accent": d["accent"],
                    "autostart": autostart.enabled(),
                    "autostart_available": autostart.available(),
                },
                "core": {
                    "installed": self.core.installed(),
                    "version": self.core.version(),
                    "install": self.core.install_state,
                },
                "data_dir": str(self.home),
            }

    def poll(self, since: int = 0) -> dict:
        return {"state": self.state(), "logs": self.logs.since(int(since))}

    # ---- servers -------------------------------------------------------
    def add_links(self, text: str) -> dict:
        added, skipped = 0, []
        for raw in (text or "").splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.lower().startswith(("http://", "https://")):
                try:
                    res = self.add_sub(line)
                    added += res["added"]
                    skipped += res["skipped"]
                except ApiError as exc:
                    skipped.append(f"подписка: {exc}")
                continue
            try:
                v = self._parse(line)
            except ApiError as exc:
                skipped.append(f"{line[:40]}…: {exc}")
                continue
            with self.lock:
                if any(s["link"] == line for s in self.data["servers"]):
                    skipped.append(f"{v.name}: уже есть в списке")
                    continue
                sid = new_id()
                self.data["servers"].append({"id": sid, "name": v.name, "link": line, "sub": None})
                if not self.data["selected"]:
                    self.data["selected"] = sid
                added += 1
        self.store.save()
        if added:
            self.say(f"добавлено серверов: {added}")
        return {"added": added, "skipped": skipped}

    def add_sub(self, url: str) -> dict:
        url = url.strip()
        try:
            result = fetch_subscription(url)
        except ValueError as exc:
            raise ApiError(str(exc)) from exc
        except OSError as exc:
            raise ApiError(f"не удалось загрузить подписку: {exc}") from exc

        parsed, skipped = [], []
        for line in result.lines:
            if not is_supported(line):
                skipped.append(f"{line.split('://')[0][:12]}:// не поддерживается, пропущено")
                continue
            try:
                parsed.append((line, parse_link(line)))
            except ValueError as exc:
                skipped.append(f"{line[:30]}…: {exc}")
        if not parsed:
            raise ApiError("в подписке нет ни одной пригодной ссылки (vless, trojan, ss, vmess)")

        with self.lock:
            d = self.data
            sub = next((s for s in d["subscriptions"] if s["url"] == url), None)
            if sub is None:
                sub = {"id": new_id(), "url": url, "name": "", "updated_at": None, "info": {}}
                d["subscriptions"].append(sub)
            sub["name"] = result.title or sub.get("name") or ""
            sub["info"] = result.info
            sub["updated_at"] = time.time()

            old = {s["link"]: s for s in d["servers"] if s.get("sub") == sub["id"]}
            current = d["selected"]
            d["servers"] = [s for s in d["servers"] if s.get("sub") != sub["id"]]
            for link, v in parsed:
                prev = old.get(link)
                d["servers"].append({
                    "id": prev["id"] if prev else new_id(),
                    # a name the user typed survives a refresh
                    "name": prev["name"] if prev and prev.get("renamed") else v.name,
                    "renamed": bool(prev and prev.get("renamed")),
                    "link": link, "sub": sub["id"],
                })
            ids = {s["id"] for s in d["servers"]}
            if current not in ids:
                d["selected"] = d["servers"][0]["id"] if d["servers"] else None
                if self.connected:
                    self.say("сервер, к которому ты подключён, исчез из подписки")
        self.store.save()
        self.say(f"подписка обновлена: {len(parsed)} серверов, пропущено {len(skipped)}")
        self.warn_expiring()
        return {"added": len(parsed), "skipped": skipped}

    def refresh_subs(self, id: str | None = None) -> dict:  # noqa: A002 - API field name
        subs = [self._find_sub(id)] if id else list(self.data["subscriptions"])
        if not subs:
            raise ApiError("подписок пока нет")
        total, skipped = 0, []
        for sub in subs:
            try:
                res = self.add_sub(sub["url"])
                total += res["added"]
                skipped += res["skipped"]
            except ApiError as exc:
                skipped.append(str(exc))
                if id:
                    raise
        return {"added": total, "skipped": skipped}

    def delete_sub(self, id: str) -> dict:  # noqa: A002
        with self.lock:
            self._find_sub(id)
            own = {s["id"] for s in self.data["servers"] if s.get("sub") == id}
            if self.connected and self.data["selected"] in own:
                raise ApiError("сначала отключись: активный сервер из этой подписки")
            self.data["servers"] = [s for s in self.data["servers"] if s["id"] not in own]
            self.data["subscriptions"] = [s for s in self.data["subscriptions"] if s["id"] != id]
            for sid in own:
                self.pings.pop(sid, None)
                self.delays.pop(sid, None)
            if self.data["selected"] in own:
                servers = self.data["servers"]
                self.data["selected"] = servers[0]["id"] if servers else None
        self.store.save()
        self.say(f"подписка удалена ({len(own)} серверов)")
        return {}

    def delete(self, id: str) -> dict:  # noqa: A002
        with self.lock:
            if self.connected and self.data["selected"] == id:
                raise ApiError("сначала отключись от этого сервера")
            self._find(id)
            self.data["servers"] = [s for s in self.data["servers"] if s["id"] != id]
            self.pings.pop(id, None)
            self.delays.pop(id, None)
            if self.data["selected"] == id:
                servers = self.data["servers"]
                self.data["selected"] = servers[0]["id"] if servers else None
        self.store.save()
        return {}

    def rename(self, id: str, name: str) -> dict:  # noqa: A002
        name = " ".join(str(name).split())[:80]
        if not name:
            raise ApiError("имя не может быть пустым")
        with self.lock:
            server = self._find(id)
            flag, _ = split_flag(server["name"])
            keep = server["name"][:2] + " " if flag else ""     # keep the country flag
            server["name"] = keep + name
            server["renamed"] = True
        self.store.save()
        return {}

    def get_link(self, id: str) -> dict:  # noqa: A002
        """The full vless:// link (contains the key!) - only on an explicit 'copy'."""
        return {"link": self._find(id)["link"]}

    def select(self, id: str) -> dict:  # noqa: A002
        with self.lock:
            self._find(id)
            changed = self.data["selected"] != id
            self.data["selected"] = id
            self.store.save()
            if changed and self.connected:
                self._reconnect()
        return {}

    def select_best(self) -> dict:
        """Measure everything, pick the fastest. Prefers the delay through the tunnel."""
        self.ping("all")
        if self.core.installed():
            try:
                self.real_ping("all")
            except ApiError:
                pass   # fall back to the TCP numbers
        with self.lock:
            known = {s["id"] for s in self.data["servers"]}
            alive = [(ms, sid) for sid, ms in self.delays.items() if ms and ms > 0 and sid in known]
            if not alive:
                # no tunnel numbers: use TCP, but never a server whose tunnel is known broken
                alive = [(ms, sid) for sid, ms in self.pings.items()
                         if ms and ms > 0 and sid in known and self.delays.get(sid) != -1]
        if not alive:
            raise ApiError("ни один сервер не ответил на проверку")
        ms, best = min(alive)
        self.say(f"самый быстрый отклик: {split_flag(self._find(best)['name'])[1]} ({ms} мс)")
        self.select(best)
        return {"id": best, "ms": ms}

    # ---- settings ------------------------------------------------------
    def set_mode(self, mode: str) -> dict:
        if mode not in MODES:
            raise ApiError("неизвестный режим")
        with self.lock:
            changed = self.data["mode"] != mode
            self.data["mode"] = mode
            self.store.save()
            if changed and self.connected:
                self._reconnect()
        return {}

    def set_settings(self, **changes) -> dict:
        allowed = set(BOOL_SETTINGS) | {"socks_port", "http_port", "loglevel", "theme", "accent", "presets",
                                        "direct_domains", "proxy_domains", "autostart"}
        unknown = set(changes) - allowed
        if unknown:
            raise ApiError(f"неизвестная настройка: {', '.join(sorted(unknown))}")

        with self.lock:
            d = self.data
            new = {k: d[k] for k in allowed if k in d}
            for key in BOOL_SETTINGS:
                if key in changes:
                    new[key] = bool(changes[key])
            for key in ("socks_port", "http_port"):
                if key in changes:
                    try:
                        new[key] = int(changes[key])
                    except (TypeError, ValueError):
                        raise ApiError("порт должен быть числом") from None
                if not (1024 <= new[key] <= 65535):
                    raise ApiError("порты должны быть в диапазоне 1024–65535")
            if new["socks_port"] == new["http_port"]:
                raise ApiError("порты SOCKS и HTTP должны отличаться")
            if "loglevel" in changes:
                if changes["loglevel"] not in LOG_LEVELS:
                    raise ApiError("неизвестный уровень журнала")
                new["loglevel"] = changes["loglevel"]
            for key in ("direct_domains", "proxy_domains"):
                if key in changes:
                    new[key] = clean_list(changes[key])
            if "presets" in changes:
                chosen = clean_list(changes["presets"])
                if any(name not in PRESETS for name in chosen):
                    raise ApiError("неизвестный набор правил")
                new["presets"] = [name for name in PRESETS if name in chosen]   # stable order
            for key, choices in (("theme", THEMES), ("accent", ACCENTS)):
                if key in changes:
                    if changes[key] not in choices:
                        raise ApiError(f"неизвестное значение {key}")
                    new[key] = changes[key]

            if "autostart" in changes:
                try:
                    autostart.set_enabled(bool(changes["autostart"]))
                except OSError as exc:
                    raise ApiError(str(exc)) from exc

            restart = any(new[k] != d[k] for k in RESTART_KEYS)
            sys_toggled = new["sysproxy"] != d["sysproxy"]
            d.update(new)
            self.store.save()

            if self.connected:
                if restart:
                    self._reconnect()
                elif sys_toggled:
                    if d["sysproxy"]:
                        self._proxy_on()
                    else:
                        self._proxy_off()
        return {}

    # ---- connect / disconnect -----------------------------------------
    def _proxy_on(self) -> None:
        d = self.data
        if not d["proxy_active"]:
            d["proxy_backup"] = winproxy.read_current()
            d["proxy_active"] = True
            self.store.save()  # persist the way back BEFORE changing anything
        winproxy.enable(d["http_port"])
        self.say(f"системный прокси Windows → 127.0.0.1:{d['http_port']}")

    def _proxy_off(self) -> None:
        d = self.data
        if d["proxy_active"]:
            winproxy.restore(d["proxy_backup"])
            d["proxy_active"] = False
            d["proxy_backup"] = None
            self.store.save()
            self.say("системный прокси возвращён как был")

    def recover_proxy(self) -> None:
        """Called at startup: undo a proxy left behind by a crash."""
        if self.data["proxy_active"]:
            self.say("в прошлый раз приложение закрылось аварийно, возвращаю прокси")
            self._proxy_off()

    def connect(self, id: str | None = None) -> dict:  # noqa: A002
        with self.lock:
            if id:
                self._find(id)
                if self.data["selected"] != id:
                    if self.connected:
                        self._stop_session()
                    self.data["selected"] = id
                    self.store.save()
            if self.connected or self.connecting:
                return {}
            sid = self.data["selected"]
            if not sid:
                raise ApiError("сначала добавь сервер")
            server = self._find(sid)
            v = self._parse(server["link"])
            self.connecting = True
            self._cancel_reconnect = False
        try:
            d = self.data
            if not self.core.installed():
                self.say("ядро Xray не установлено, скачиваю автоматически")
                try:
                    self.core.install_blocking()
                except CoreError as exc:
                    raise ApiError(f"{exc}\n{self.core.manual_hint()}") from exc
            self.metrics_port = free_port()
            config = build_config(
                v, d["mode"], d["socks_port"], d["http_port"], d["loglevel"],
                d["direct_domains"], d["proxy_domains"],
                metrics_port=self.metrics_port, show_connections=d["show_connections"],
                presets=d["presets"])
            title = split_flag(server["name"])[1]
            self.say(f"подключаюсь: {title} ({v.host}:{v.port}, {v.protocol}, {v.security}/{v.network})")
            try:
                self.core.start(config, wait_port=d["http_port"])
            except CoreError as exc:
                raise ApiError(str(exc)) from exc
            try:
                if d["sysproxy"]:
                    self._proxy_on()
            except Exception as exc:  # noqa: BLE001
                self.core.stop()
                raise ApiError(f"не удалось включить системный прокси: {exc}") from exc
            with self.lock:
                self._gen += 1
                self.traffic.reset()
                self.health = {"ms": None, "fails": 0, "checked_at": None}
                self.exit = None
                self.speed = None
                self._next_health = 0.0      # probe the tunnel right away
                self._want_exit = True
                self.connected = True
                self.connected_at = time.time()
            self.say("подключено")
        except ApiError as exc:
            # A toast disappears; the journal keeps the reason.
            self.say(f"не удалось подключиться: {exc}")
            raise
        finally:
            with self.lock:
                self.connecting = False
        return {}

    def _stop_session(self) -> bool:
        """Proxy back, core down. Returns True if something was running."""
        with self.lock:
            was = self.connected or self.core.running()
            # Proxy first: otherwise browsers hang on a dead local port.
            try:
                self._proxy_off()
            except Exception as exc:  # noqa: BLE001
                self.say(f"ошибка при возврате прокси: {exc}")
            self.core.stop()
            self._gen += 1
            self.connected = False
            self.connected_at = None
            self.traffic.reset()
            self.health = {"ms": None, "fails": 0, "checked_at": None}
            self.exit = None
            self.speed = None
        return was

    def disconnect(self) -> dict:
        self._cancel_reconnect = True      # the user said "off": stop any auto-reconnect
        if self._stop_session():
            self.say("отключено")
        return {}

    def _reconnect(self) -> None:
        self._stop_session()
        self.connect()

    # ---- background: crash watch + traffic -----------------------------
    def _ticker(self) -> None:
        while not self.quit_event.wait(1):
            try:
                died = False
                with self.lock:
                    if self.connected and not self.core.running():
                        self._stop_session()
                        died = True
                if died:
                    will_retry = self.data["auto_reconnect"] and not self._cancel_reconnect
                    self.notify("Соединение оборвалось",
                                "Восстанавливаю…" if will_retry else "Ядро Xray неожиданно завершилось.")
                if died and self.data["auto_reconnect"] and not self._cancel_reconnect:
                    threading.Thread(target=self._auto_reconnect, daemon=True).start()
                if self.connected:
                    self._read_traffic()
            except Exception:  # noqa: BLE001
                log.exception("ticker")

    def _auto_reconnect(self) -> None:
        self.reconnecting = True
        try:
            for attempt, delay in enumerate(RECONNECT_DELAYS, 1):
                if self.quit_event.wait(delay) or self._cancel_reconnect:
                    return
                self.say(f"восстанавливаю соединение, попытка {attempt} из {len(RECONNECT_DELAYS)}")
                try:
                    self.connect()
                    self.notify("Соединение восстановлено", "Снова работаю через сервер.")
                    return
                except ApiError:
                    continue
            self.notify("Соединение не восстановлено", "Три попытки не помогли, трафик идёт напрямую.")
        finally:
            self.reconnecting = False

    def _read_traffic(self) -> None:
        port = self.metrics_port
        if not port:
            return
        try:
            with make_opener(None).open(f"http://127.0.0.1:{port}/debug/vars", timeout=2) as r:
                stats = json.loads(r.read()).get("stats") or {}
        except (OSError, ValueError):
            return
        with self.lock:
            if self.connected:
                self.traffic.update(stats, time.time())

    # ---- background: is the tunnel alive? ------------------------------
    def _via_tunnel(self, url: str, timeout: float = 8.0) -> tuple[int, str]:
        """GET a URL through our own HTTP inbound. Returns (ms, body)."""
        opener = make_opener(f"http://127.0.0.1:{self.data['http_port']}")
        start = time.perf_counter()
        with opener.open(url, timeout=timeout) as r:
            body = r.read(4096).decode("utf-8", "replace")
        return max(1, int((time.perf_counter() - start) * 1000)), body

    def _health_loop(self) -> None:
        while not self.quit_event.wait(1):
            try:
                if not self.connected:
                    continue
                gen = self._gen
                if self._want_exit:
                    self._want_exit = False
                    self._fetch_exit(gen)
                if time.time() < self._next_health:
                    continue
                self._next_health = time.time() + HEALTH_INTERVAL
                self._probe(gen)
            except Exception:  # noqa: BLE001
                log.exception("health loop")

    def _probe(self, gen: int) -> None:
        try:
            ms, _ = self._via_tunnel(HEALTH_URL)
        except Exception:  # noqa: BLE001 - any failure means "no answer"
            ms = None
        with self.lock:
            if gen != self._gen or not self.connected:
                return                       # that session is already gone
            before = self.health["fails"]
            fails = 0 if ms is not None else before + 1
            self.health = {"ms": ms, "fails": fails, "checked_at": time.time()}
        if fails == HEALTH_FAILS:
            self.notify("Сервер не отвечает", f"{HEALTH_FAILS} проверки подряд без ответа.")
        elif ms is not None and before >= HEALTH_FAILS:
            self.notify("Сервер снова отвечает", "Соединение в порядке.")
        if fails >= HEALTH_FAILS and self.data["failover"]:
            self._failover()

    def _fetch_exit(self, gen: int) -> dict | None:
        try:
            ms, body = self._via_tunnel(TRACE_URL, timeout=10)
        except Exception as exc:  # noqa: BLE001
            self.say(f"не удалось узнать выходной IP: {exc}")
            return None
        info = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
        result = {"ip": info.get("ip", "?"), "loc": info.get("loc", "?"), "ms": ms}
        with self.lock:
            if gen != self._gen:
                return None
            self.exit = result
        self.say(f"выходной IP {result['ip']} ({result['loc']})")
        return result

    def _failover(self) -> None:
        if time.time() - self._last_failover < FAILOVER_COOLDOWN:
            return
        self._last_failover = time.time()
        current = self.data["selected"]
        self.ping("all")
        known = {s["id"] for s in self.data["servers"]}
        alive = sorted((ms, sid) for sid, ms in self.pings.items()
                       if ms and ms > 0 and sid != current and sid in known)
        if not alive:
            self.say("переключаться некуда: остальные серверы тоже не отвечают")
            return
        ms, target = alive[0]
        self.notify("Переключаюсь на другой сервер", f"{split_flag(self._find(target)['name'])[1]}, отклик {ms} мс.")
        try:
            self.select(target)
        except ApiError:
            pass   # the reason is already in the journal

    def shutdown(self) -> None:
        self._cancel_reconnect = True
        try:
            self._stop_session()
        except Exception:  # noqa: BLE001
            log.exception("shutdown")
        self.quit_event.set()

    def startup(self) -> None:
        """Things done once after launch, in the background."""
        threading.Thread(target=self._startup, daemon=True).start()

    def _startup(self) -> None:
        d = self.data
        if d["sub_auto_update"]:
            for sub in list(d["subscriptions"]):
                if time.time() - (sub.get("updated_at") or 0) > SUB_MAX_AGE:
                    try:
                        self.add_sub(sub["url"])
                    except ApiError as exc:
                        self.say(f"подписка не обновилась: {exc}")
        self.warn_expiring()
        if d["auto_connect"] and d["selected"]:
            try:
                self.connect()
            except ApiError:
                pass   # already in the journal
        self.check_update()

    def warn_expiring(self) -> None:
        """One reminder per subscription per run when its paid period is about to end."""
        now = time.time()
        for sub in self.data["subscriptions"]:
            expire = (sub.get("info") or {}).get("expire") or 0
            if not expire or sub["id"] in self._expiry_warned:
                continue
            days = int((expire - now) // 86400)
            name = sub.get("name") or urlsplit(sub["url"]).hostname or "подписка"
            if days < 0:
                self._expiry_warned.add(sub["id"])
                self.notify("Подписка закончилась", f"{name}: срок истёк, серверы могут не работать.")
            elif days <= EXPIRY_WARN_DAYS:
                self._expiry_warned.add(sub["id"])
                left = "сегодня" if days == 0 else f"через {days} дн."
                self.notify("Подписка скоро закончится", f"{name}: срок истекает {left}.")

    def check_update(self) -> dict:
        """Is there a newer release on GitHub? Only looks, never downloads anything."""
        if not UPDATE_REPO:
            return {"configured": False, "update": None}
        url = UPDATE_URL.format(repo=UPDATE_REPO)
        try:
            with make_opener(None).open(url, timeout=10) as r:
                final = r.geturl()            # GitHub redirects to the newest tag
        except Exception as exc:  # noqa: BLE001
            log.info("update check failed: %s", exc)
            return {"configured": True, "update": None, "error": explain_error(exc)}
        latest = parse_version(final)
        if latest and latest > parse_version(__version__):
            self.update = {"version": ".".join(map(str, latest)), "url": final}
            self.notify("Вышла новая версия", f"Umbra {self.update['version']}. Открой окно, чтобы скачать.")
        else:
            self.update = None
        return {"configured": True, "update": self.update}

    def open_update(self) -> dict:
        """Open the release page in the default browser (only the URL we found ourselves)."""
        if not self.update:
            raise ApiError("обновлений нет")
        import webbrowser
        webbrowser.open(self.update["url"])
        return {}

    def qr(self, id: str) -> dict:  # noqa: A002
        """QR code of a server link, to scan with a phone. Contains the access key."""
        server = self._find(id)
        try:
            rows = make_qr(server["link"])
        except ValueError as exc:
            raise ApiError(str(exc)) from exc
        return {"rows": rows, "name": split_flag(server["name"])[1]}

    # ---- diagnostics ---------------------------------------------------
    def ping(self, id: str = "all") -> dict:  # noqa: A002
        with self.lock:
            targets = list(self.data["servers"]) if id == "all" else [self._find(id)]
        jobs = []
        for s in targets:
            try:
                v = parse_link(s["link"])
            except ValueError:
                self.pings[s["id"]] = -1
                continue
            jobs.append((s["id"], v.host, v.port))
        if jobs:
            with ThreadPoolExecutor(max_workers=16) as pool:
                for sid, ms in zip((j[0] for j in jobs),
                                   pool.map(lambda j: tcp_ping(j[1], j[2]), jobs)):
                    self.pings[sid] = ms
        return {}

    def real_ping(self, id: str = "all") -> dict:  # noqa: A002
        """Time one web request through every server's own tunnel.

        Unlike the TCP ping this proves the keys and the transport really work.
        A second, temporary Xray is used, so the live connection is not touched.
        """
        if not self.core.installed():
            raise ApiError("для проверки через туннель нужно ядро Xray: "
                           "подключись один раз, оно скачается само")
        with self.lock:
            targets = list(self.data["servers"]) if id == "all" else [self._find(id)]
        servers, used = [], set()
        for s in targets:
            try:
                v = parse_link(s["link"])
            except ValueError:
                self.delays[s["id"]] = -1
                continue
            port = free_port()
            while port in used:
                port = free_port()
            used.add(port)
            servers.append((s["id"], v, port))
        if not servers:
            return {}

        try:
            proc = self.core.run_probe(build_probe_config(servers), wait_port=servers[0][2])
        except CoreError:
            # One broken link (for example a bad Reality key) spoils the whole
            # batch: find the culprits one by one and go on without them.
            good = []
            for item in servers:
                if self.core.config_ok(build_probe_config([item])):
                    good.append(item)
                else:
                    self.delays[item[0]] = -1
            servers = good
            if not servers:
                return {}
            try:
                proc = self.core.run_probe(build_probe_config(servers), wait_port=servers[0][2])
            except CoreError as exc:
                raise ApiError(f"не удалось запустить проверку: {exc}") from exc
        try:
            with ThreadPoolExecutor(max_workers=8) as pool:
                for sid, ms in zip((s[0] for s in servers),
                                   pool.map(lambda s: self._timed_get(s[2]), servers)):
                    self.delays[sid] = ms
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:  # noqa: BLE001
                proc.kill()
        return {}

    @staticmethod
    def _timed_get(port: int) -> int:
        """Best of two requests: the first one also pays for the tunnel handshake,
        so on its own it makes every server look slow."""
        opener = make_opener(f"http://127.0.0.1:{port}")
        best = -1
        for _ in range(2):
            start = time.perf_counter()
            try:
                with opener.open(HEALTH_URL, timeout=PROBE_TIMEOUT) as r:
                    r.read(1024)
            except Exception:  # noqa: BLE001 - any failure = this tunnel does not work
                break
            ms = max(1, int((time.perf_counter() - start) * 1000))
            best = ms if best < 0 else min(best, ms)
        return best

    def speedtest(self) -> dict:
        """Download through the active tunnel for a few seconds, report Mbit/s."""
        if not self.connected:
            raise ApiError("сначала подключись")
        gen = self._gen
        opener = make_opener(f"http://127.0.0.1:{self.data['http_port']}")
        total, elapsed, source, problems = 0, 0.0, "", []
        for url in SPEED_URLS:                 # the first host that answers is used
            host = urlsplit(url).hostname or url
            try:
                with opener.open(url, timeout=10) as r:
                    start = time.perf_counter()
                    while time.perf_counter() - start < SPEED_SECONDS:
                        chunk = r.read(64 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                    elapsed = time.perf_counter() - start
            except Exception as exc:  # noqa: BLE001
                problems.append(f"{host}: {explain_error(exc) if not isinstance(exc, HTTPError) else exc}")
                total = 0
                continue
            if total > 0 and elapsed > 0:
                source = host
                break
            problems.append(f"{host}: ничего не прислал")
        if not source:
            raise ApiError("тест скорости не прошёл ни с одним сервером:\n" + "\n".join(problems))
        result = {"mbps": round(total * 8 / elapsed / 1_000_000, 1), "bytes": total,
                  "seconds": round(elapsed, 1), "at": time.time(), "source": source}
        with self.lock:
            if gen == self._gen:
                self.speed = result
        self.say(f"тест скорости: {result['mbps']} Мбит/с (файл с {source})")
        return result

    def check_site(self, target: str) -> dict:
        """Is a site reachable straight from this PC, and through the selected server?

        "Through the server" uses a temporary Xray with only that server, so the
        answer does not depend on the routing rules or on being connected.
        """
        target = (target or "").strip()
        if not target:
            raise ApiError("введи адрес сайта")
        if "://" not in target:
            target = "https://" + target
        parts = urlsplit(target)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ApiError("адрес должен выглядеть как example.com или https://example.com")
        url = f"{parts.scheme}://{parts.netloc}{parts.path or '/'}"
        host = parts.hostname

        result: dict = {"host": host, "url": url, "direct": None, "server": None, "server_name": None,
                        "server_note": None}
        with ThreadPoolExecutor(max_workers=2) as pool:
            direct_job = pool.submit(probe_url, url, None)
            server_job = pool.submit(self._probe_via_selected, url)
            result["direct"] = direct_job.result()
            result["server"], result["server_name"], result["server_note"] = server_job.result()

        d, s = result["direct"], result["server"]
        if d["ok"] and s and s["ok"]:
            verdict = "both"
        elif d["ok"]:
            verdict = "direct_only" if s else "direct"
        elif s and s["ok"]:
            verdict = "server_only"
        elif s:
            verdict = "none"
        else:
            verdict = "direct_fail"
        result["verdict"] = verdict
        self.say(f"проверка {host}: напрямую {'да' if d['ok'] else 'нет'}, "
                 f"через сервер {'да' if s and s['ok'] else ('нет' if s else 'не проверялось')}")
        return result

    def _probe_via_selected(self, url: str) -> tuple[dict | None, str | None, str | None]:
        """(result, server name, note). result=None when the check could not be made."""
        sid = self.data["selected"]
        if not sid:
            return None, None, "сервер не выбран"
        if not self.core.installed():
            return None, None, "ядро Xray ещё не скачано: подключись один раз"
        try:
            server = self._find(sid)
            link = parse_link(server["link"])
        except (ApiError, ValueError) as exc:
            return None, None, str(exc)
        name = split_flag(server["name"])[1]
        port = free_port()
        try:
            proc = self.core.run_probe(build_probe_config([(sid, link, port)]), wait_port=port)
        except CoreError as exc:
            return None, name, str(exc)
        try:
            return probe_url(url, f"http://127.0.0.1:{port}"), name, None
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:  # noqa: BLE001
                proc.kill()

    def add_rule(self, host: str, route: str) -> dict:
        """Remember "this site always goes direct / through the server"."""
        host = (host or "").strip().lower()
        if not host or " " in host or route not in ("direct", "proxy"):
            raise ApiError("неверное правило")
        d = self.data
        direct = [x for x in d["direct_domains"] if x != host]
        proxy = [x for x in d["proxy_domains"] if x != host]
        (direct if route == "direct" else proxy).append(host)
        self.set_settings(direct_domains=direct, proxy_domains=proxy)
        self.say(f"правило: {host} всегда {'напрямую' if route == 'direct' else 'через сервер'}")
        return {}

    def test(self) -> dict:
        """Ask again which IP the world sees + probe the tunnel now."""
        if not self.connected:
            raise ApiError("сначала подключись")
        gen = self._gen
        self._probe(gen)
        result = self._fetch_exit(gen)
        if result is None:
            raise ApiError("туннель не ответил на проверку")
        return result

    def install_core(self) -> dict:
        if self.connected:
            raise ApiError("сначала отключись")
        if self.core.install_state["running"]:
            return {}
        self.core.install_async()
        return {}

    def open_data_dir(self) -> dict:
        if sys.platform != "win32":
            raise ApiError(f"папка данных: {self.home}")
        os.startfile(str(self.home))  # noqa: S606 - our own folder
        return {}

    def quit(self) -> dict:
        self.quit_event.set()
        return {}

    # ---- dispatch ------------------------------------------------------
    def call(self, name: str, args: dict) -> dict:
        methods = {
            "poll": self.poll, "add_links": self.add_links, "add_sub": self.add_sub,
            "refresh_subs": self.refresh_subs, "delete_sub": self.delete_sub,
            "delete": self.delete, "rename": self.rename, "get_link": self.get_link,
            "select": self.select, "select_best": self.select_best,
            "set_mode": self.set_mode, "set_settings": self.set_settings,
            "connect": self.connect, "disconnect": self.disconnect, "ping": self.ping,
            "real_ping": self.real_ping, "speedtest": self.speedtest,
            "check_site": self.check_site, "add_rule": self.add_rule, "qr": self.qr,
            "check_update": self.check_update, "open_update": self.open_update,
            "test": self.test, "install_core": self.install_core,
            "open_data_dir": self.open_data_dir, "quit": self.quit,
        }
        method = methods.get(name)
        if method is None:
            raise ApiError(f"неизвестный метод: {name}")
        try:
            inspect.signature(method).bind(**args)  # validate arguments only
        except TypeError as exc:
            raise ApiError(f"неверные аргументы: {exc}") from exc
        return method(**args)
