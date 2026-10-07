"""Persistent state: state.json in the data folder (atomic writes).

Data folder, in order of priority:
  1. UMBRA_HOME environment variable (tests);
  2. "data" folder next to the .exe, if it exists (portable mode, e.g. USB stick);
  3. %APPDATA%\\Umbra (normal mode).
"""
from __future__ import annotations

import copy
import json
import os
import secrets
import shutil
import sys
import threading
from pathlib import Path

DEFAULT_STATE: dict = {
    "servers": [],          # [{"id", "name", "link", "sub": <subscription id> | None}]
    "subscriptions": [],    # [{"id", "url", "name", "updated_at", "info"}]
    "selected": None,
    "mode": "bypass_ru",
    "sysproxy": True,
    "socks_port": 10808,
    "http_port": 10809,
    "loglevel": "error",         # Xray's "warning" level is mostly routine connection noise
    "show_connections": False,   # Xray access log (every connection) in the journal
    "direct_domains": [],        # always direct
    "proxy_domains": [],         # always through the tunnel (wins over "direct" rules)
    "presets": [],               # ready-made rule sets, see xrayconf.PRESETS
    "notifications": True,       # tray balloons about lost connection, failover, expiry
    "auto_connect": False,       # connect when the app starts
    "auto_reconnect": True,      # restart the core if it dies
    "failover": False,           # switch server when the tunnel stops answering
    "sub_auto_update": True,     # refresh subscriptions older than 12 h at start
    "close_to_tray": True,       # closing the window keeps the app running in the tray
    "theme": "dark",             # dark | light
    "accent": "teal",            # colour of "through the server" in the UI
    # Set while WE have changed the Windows proxy; lets us undo it after a crash.
    "proxy_active": False,
    "proxy_backup": None,
    "state_version": 2,          # bumped when a one-time migration is needed
}


def exe_dir() -> Path | None:
    """Folder of the .exe when running as a PyInstaller build, else None."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return None


LEGACY_DIR = "Vless" + "Client"      # the program's name before 0.6.0


def adopt_legacy_data(new: Path, old: Path) -> bool:
    """First start after the rename: copy servers, settings and the core over.

    The old folder is left untouched (it doubles as a backup); only the
    browser profile and logs are skipped, they are recreated anyway.
    """
    if new.exists() or not (old / "state.json").is_file():
        return False
    try:
        shutil.copytree(old, new, ignore=shutil.ignore_patterns("ui-profile", "app.log*", "ui.url", "probe*.json"))
    except OSError:
        shutil.rmtree(new, ignore_errors=True)     # never leave a half-copied folder behind
        return False
    return True


def home_dir() -> Path:
    override = os.environ.get("UMBRA_HOME")
    portable = exe_dir() / "data" if exe_dir() else None
    if override:
        base = Path(override)
    elif portable is not None and portable.is_dir():
        base = portable
    elif os.environ.get("APPDATA"):
        base = Path(os.environ["APPDATA"]) / "Umbra"
        adopt_legacy_data(base, Path(os.environ["APPDATA"]) / LEGACY_DIR)
    else:
        base = Path.home() / ".umbra"
    base.mkdir(parents=True, exist_ok=True)
    return base


def new_id() -> str:
    return secrets.token_hex(4)


def migrate(data: dict, loaded_version: int = 2) -> dict:
    """Bring a state.json written by an older version to the current shape."""
    if loaded_version < 2 and data.get("loglevel") == "warning":
        data["loglevel"] = "error"       # 0.5.0: the old default flooded the journal
    subs = []
    url_to_id: dict[str, str] = {}
    for item in data.get("subscriptions", []):
        if isinstance(item, str):                      # v0.1: plain list of URLs
            item = {"id": new_id(), "url": item, "name": "", "updated_at": None, "info": {}}
        if not isinstance(item, dict) or not item.get("url"):
            continue
        item.setdefault("id", new_id())
        item.setdefault("name", "")
        item.setdefault("updated_at", None)
        item.setdefault("info", {})
        url_to_id[item["url"]] = item["id"]
        subs.append(item)
    data["subscriptions"] = subs
    ids = {s["id"] for s in subs}
    for server in data.get("servers", []):
        ref = server.get("sub")
        if ref in url_to_id:                           # v0.1 stored the URL here
            server["sub"] = url_to_id[ref]
        elif ref not in ids:
            server["sub"] = None
    return data


class Store:
    def __init__(self, home: Path):
        self.path = home / "state.json"
        self.lock = threading.RLock()
        self.data: dict = copy.deepcopy(DEFAULT_STATE)
        self._load()

    def _load(self) -> None:
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            # Corrupted file: keep it for inspection, start clean.
            try:
                self.path.replace(self.path.with_suffix(".json.bad"))
            except OSError:
                pass
            return
        if isinstance(loaded, dict):
            for key in DEFAULT_STATE:
                if key in loaded:
                    self.data[key] = loaded[key]
            self.data = migrate(self.data, int(loaded.get("state_version") or 1))
            self.data["state_version"] = DEFAULT_STATE["state_version"]

    def save(self) -> None:
        with self.lock:
            tmp = self.path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(tmp, self.path)
