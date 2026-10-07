"""Entry point: start the local server, open the UI window, clean up on exit."""
from __future__ import annotations

import argparse
import atexit
import logging
import logging.handlers
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

from . import autostart, sysproxy
from .controller import Controller
from .server import UiServer
from .store import Store, exe_dir, home_dir
from .tray import Tray, focus_window

LOCK_PORT = 47813           # held while an instance runs (single-instance lock)
WINDOW_TITLE = "Umbra"   # must match <title> in web/index.html
HEARTBEAT_TIMEOUT = 900     # only used when we cannot watch the browser process (seconds)


def find_browser() -> str | None:
    """Edge ships with Windows 10/11; Chrome is the fallback."""
    candidates: list[str] = []
    for env in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"):
        base = os.environ.get(env)
        if base:
            candidates += [
                os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe"),
                os.path.join(base, "Google", "Chrome", "Application", "chrome.exe"),
            ]
    for path in candidates:
        if os.path.exists(path):
            return path
    for name in ("msedge", "chrome", "google-chrome", "chromium", "chromium-browser"):
        found = shutil.which(name)
        if found:
            return found
    return None


def launch_window(url: str, home: Path) -> subprocess.Popen | None:
    """Open the UI as a standalone app window (no tabs, no address bar).

    A private --user-data-dir makes the browser start its own process that
    lives exactly as long as our window: when it exits we know the user
    closed the window and can shut down cleanly.
    """
    browser = find_browser()
    if not browser:
        return None
    profile = home / "ui-profile"
    profile.mkdir(exist_ok=True)
    args = [
        browser, f"--app={url}", f"--user-data-dir={profile}",
        "--window-size=1180,800", "--no-first-run", "--no-default-browser-check",
        "--disable-features=Translate,msEdgeSidebarV2", "--disable-sync",
        "--disable-background-mode",   # window closed = browser process ends
    ]
    try:
        return subprocess.Popen(args, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        return None


def setup_logging(home: Path, verbose: bool) -> None:
    handler = logging.handlers.RotatingFileHandler(
        home / "app.log", maxBytes=512 * 1024, backupCount=2, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.addHandler(handler)
    if verbose and sys.stderr:
        root.addHandler(logging.StreamHandler())


def say(text: str) -> None:
    """print() that survives a windowed .exe, where there is no console at all."""
    if sys.stdout:
        try:
            print(text)
        except OSError:
            pass


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="umbra")
    ap.add_argument("--restore-proxy", action="store_true",
                    help="вернуть прокси Windows из бэкапа и выйти")
    ap.add_argument("--no-window", action="store_true", help="не открывать окно, только напечатать URL")
    ap.add_argument("--tray", action="store_true", help="запуститься свёрнутым в трей (для автозапуска)")
    ap.add_argument("--port", type=int, default=0, help="фиксированный порт UI (для отладки)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    home = home_dir()
    setup_logging(home, args.verbose)
    url_file = home / "ui.url"

    if args.restore_proxy:
        store = Store(home)
        if store.data["proxy_active"]:
            sysproxy.restore(store.data["proxy_backup"])
            store.data["proxy_active"], store.data["proxy_backup"] = False, None
            store.save()
            say("системный прокси возвращён из бэкапа")
        else:
            sysproxy.restore(None)
            say("бэкапа не было: системный прокси просто выключен")
        return 0

    # Single instance: two copies would fight over the Xray ports.
    lock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        lock.bind(("127.0.0.1", LOCK_PORT))
    except OSError:
        # Already running: show its window instead of doing nothing.
        if not focus_window(WINDOW_TITLE):
            try:
                launch_window(url_file.read_text(encoding="utf-8").strip(), home)
            except OSError:
                pass
        say("Umbra уже запущен.")
        return 1

    autostart.drop_legacy()
    ctrl = Controller(home)
    ctrl.recover_proxy()
    if exe_dir():
        ctrl.core.seed_from(exe_dir() / "core")     # portable: core lying next to the .exe
    server = UiServer(ctrl, args.port)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    window = {"proc": None, "started": 0.0, "detached": False}

    def open_window() -> None:
        """Show the UI: focus the existing window or start a new one."""
        if focus_window(WINDOW_TITLE):
            return
        proc = launch_window(server.url, home)
        if proc is None:
            webbrowser.open(server.url)
            window["detached"] = True
        window["proc"], window["started"] = proc, time.time()

    # ---- tray ---------------------------------------------------------
    tray: Tray | None = None

    def tray_state() -> dict:
        busy = ctrl.connecting or ctrl.reconnecting
        return {"connected": ctrl.connected, "busy": busy, "can_connect": bool(ctrl.data["selected"]),
                "tip": tray_tip()}

    def tray_tip() -> str:
        name = ""
        for s in ctrl.data["servers"]:
            if s["id"] == ctrl.data["selected"]:
                name = s["name"]
        if ctrl.connecting or ctrl.reconnecting:
            return "Umbra: подключаюсь…"
        if ctrl.connected:
            return f"Umbra: подключено, {name}"
        return "Umbra: отключено"

    def tray_toggle() -> None:
        from .controller import ApiError
        try:
            if ctrl.connected or ctrl.reconnecting:
                ctrl.disconnect()
            else:
                ctrl.connect()
        except ApiError as exc:
            if tray:
                tray.balloon("Не удалось подключиться", str(exc))

    if not args.no_window:
        tray = Tray(tray_state, open_window, tray_toggle, ctrl.quit_event.set)
        ctrl.tray_active = tray.start()
        if ctrl.tray_active:
            ctrl.notify_hook = tray.balloon
        else:
            tray = None

    cleaned = threading.Event()

    def cleanup(*_):
        if not cleaned.is_set():
            cleaned.set()
            ctrl.shutdown()
            if tray:
                tray.stop()
            try:
                url_file.unlink()
            except OSError:
                pass

    atexit.register(cleanup)
    for sig in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, sig):
            signal.signal(getattr(signal, sig), lambda *_: ctrl.quit_event.set())

    say(f"UI: {server.url}")
    logging.getLogger("umbra").info("UI on port %s, tray=%s", server.port, ctrl.tray_active)
    try:
        url_file.write_text(server.url, encoding="utf-8")   # lets a second launch reopen the window
    except OSError:
        pass

    ctrl.startup()

    start_hidden = args.tray and ctrl.tray_active       # autostart: sit in the tray, no window
    if not args.no_window and not start_hidden:
        open_window()

    hinted = False
    while not ctrl.quit_event.is_set():
        time.sleep(0.5)
        proc = window["proc"]
        if proc is not None and proc.poll() is not None:
            window["proc"] = None
            if time.time() - window["started"] <= 5:
                window["detached"] = True      # the launcher handed the window to another process
            elif ctrl.tray_active and ctrl.data["close_to_tray"]:
                if not hinted and tray:        # the window was closed: stay in the tray, say so once
                    hinted = True
                    tray.balloon("Umbra работает в фоне",
                                 "Значок возле часов: щелчок открывает окно, правая кнопка показывает меню.")
            else:
                break                          # no tray (or the user prefers it): closing = quitting
        if (window["detached"] and not ctrl.tray_active and not args.no_window
                and time.time() - ctrl.last_seen > HEARTBEAT_TIMEOUT):
            break                              # nobody is polling any more
        if tray:
            tray.set_tip(tray_tip())

    cleanup()
    server.shutdown()
    proc = window["proc"]
    if proc is not None and proc.poll() is None:
        proc.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
