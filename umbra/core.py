"""Managing the Xray-core binary: download, verify, run, stop, collect logs."""
from __future__ import annotations

import hashlib
import http.client
import io
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import zipfile
from collections import deque
from pathlib import Path

RELEASE_BASE = "https://github.com/XTLS/Xray-core/releases/latest/download/"
USER_AGENT = "Umbra/0.1"
# Only these files are taken out of the release archive (no path tricks).
WANTED_FILES = ("geoip.dat", "geosite.dat", "LICENSE")
# The first launch of a freshly downloaded xray.exe can be slow (antivirus scan).
START_TIMEOUT = 20


class CoreError(Exception):
    """Human-readable problem with the core (shown in the UI)."""


class LogBuffer:
    """Ring buffer with increasing sequence numbers for incremental polling."""

    def __init__(self, maxlen: int = 1000):
        self._items: deque = deque(maxlen=maxlen)
        self._n = 0
        self._lock = threading.Lock()

    def add(self, src: str, text: str) -> None:
        with self._lock:
            self._n += 1
            self._items.append({
                "n": self._n,
                "ts": time.strftime("%H:%M:%S"),
                "src": src,
                "text": text.rstrip("\r\n"),
            })

    def since(self, n: int) -> list[dict]:
        with self._lock:
            return [item for item in self._items if item["n"] > n]

    def tail(self, count: int = 8) -> list[str]:
        with self._lock:
            return [item["text"] for item in list(self._items)[-count:]]


def _asset_name() -> str:
    machine = platform.machine().lower()
    arm = machine in ("arm64", "aarch64")
    if sys.platform == "win32":
        return "Xray-windows-arm64-v8a.zip" if arm else "Xray-windows-64.zip"
    if sys.platform == "darwin":
        return "Xray-macos-arm64-v8a.zip" if arm else "Xray-macos-64.zip"
    return "Xray-linux-arm64-v8a.zip" if arm else "Xray-linux-64.zip"


def port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if sys.platform != "win32":
            # POSIX: connections in TIME_WAIT (left after a previous run) would
            # make a plain bind fail although nobody is listening. On Windows
            # SO_REUSEADDR means something else (port hijacking), so not there.
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def free_port() -> int:
    """Ask the OS for a currently unused TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def port_is_open(port: int, timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


class XrayCore:
    def __init__(self, home: Path, logs: LogBuffer):
        self.dir = home / "core"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.exe = self.dir / ("xray.exe" if sys.platform == "win32" else "xray")
        self.config_path = self.dir / "config.json"
        self.logs = logs
        self.proc: subprocess.Popen | None = None
        self.install_state = {"running": False, "pct": 0, "error": None}
        self._version: str | None = None

    # ---- environment -------------------------------------------------
    def _env(self) -> dict:
        env = dict(os.environ)
        env["XRAY_LOCATION_ASSET"] = str(self.dir)  # where geoip.dat/geosite.dat live
        return env

    def _popen_kwargs(self) -> dict:
        kwargs: dict = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        return kwargs

    def installed(self) -> bool:
        return all((self.dir / n).exists() for n in (self.exe.name, "geoip.dat", "geosite.dat"))

    def seed_from(self, folder: Path) -> bool:
        """Portable mode: take the core from a "core" folder lying next to the .exe."""
        names = (self.exe.name, "geoip.dat", "geosite.dat")
        if self.installed() or not all((folder / n).is_file() for n in names):
            return False
        for n in names:
            shutil.copy2(folder / n, self.dir / n)
        self._version = None
        self.logs.add("core", f"ядро взято из папки рядом с программой: {folder}")
        return True

    def version(self) -> str | None:
        if self._version or not self.exe.exists():
            return self._version
        try:
            out = subprocess.run(
                [str(self.exe), "version"], capture_output=True, text=True, timeout=10,
                env=self._env(), **self._popen_kwargs(),
            ).stdout
            m = re.match(r"Xray\s+(\S+)", out)
            self._version = m.group(1) if m else None
        except (OSError, subprocess.SubprocessError):
            self._version = None
        return self._version

    # ---- install -----------------------------------------------------
    def install_async(self) -> None:
        if self.install_state["running"]:
            return
        self.install_state = {"running": True, "pct": 0, "error": None}  # visible at once
        threading.Thread(target=self._install_thread, daemon=True).start()

    def _install_thread(self) -> None:
        try:
            self.install_blocking()
        except CoreError:
            pass  # already logged and stored in install_state

    def install_blocking(self) -> None:
        """install() with progress/error bookkeeping for the UI. Raises CoreError."""
        self.install_state = {"running": True, "pct": 0, "error": None}
        try:
            self.install()
        except CoreError as exc:
            self.logs.add("core", f"установка ядра не удалась: {exc}")
            self.install_state = {"running": False, "pct": 0, "error": str(exc)}
            raise
        except (OSError, http.client.HTTPException, zipfile.BadZipFile) as exc:
            err = CoreError(f"не удалось установить ядро: {exc}")
            self.logs.add("core", str(err))
            self.install_state = {"running": False, "pct": 0, "error": str(err)}
            raise err from exc
        self.install_state = {"running": False, "pct": 100, "error": None}

    def manual_hint(self) -> str:
        return (f"Если GitHub недоступен, скачай {_asset_name()} вручную "
                f"(github.com/XTLS/Xray-core/releases) и положи xray, geoip.dat, "
                f"geosite.dat в папку {self.dir}")

    def _download(self, url: str, progress=None) -> bytes:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=30) as resp:
            total = int(resp.headers.get("Content-Length") or 0)
            buf = io.BytesIO()
            while True:
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                buf.write(chunk)
                if progress and total:
                    progress(int(buf.tell() * 100 / total))
            return buf.getvalue()

    def install(self) -> None:
        """Download the latest Xray-core release, verify SHA-256, unpack."""
        if self.running():
            raise CoreError("останови ядро (Disconnect) перед обновлением")
        asset = _asset_name()
        self.logs.add("core", f"скачиваю {asset} (GitHub, XTLS/Xray-core, latest)…")

        def progress(pct: int) -> None:
            self.install_state["pct"] = pct

        try:
            archive = self._download(RELEASE_BASE + asset, progress)
            digest_text = self._download(RELEASE_BASE + asset + ".dgst").decode("utf-8", "replace")
        except OSError as exc:
            raise CoreError(f"не удалось скачать: {exc}") from exc

        match = re.search(r"SHA2-256=\s*([0-9a-fA-F]{64})", digest_text)
        if not match:
            raise CoreError("в .dgst нет SHA2-256 — отказываюсь ставить непроверенный файл")
        actual = hashlib.sha256(archive).hexdigest()
        if actual.lower() != match.group(1).lower():
            raise CoreError("SHA-256 архива не совпадает с .dgst — файл не установлен")
        self.logs.add("core", f"SHA-256 совпал ({actual[:16]}…)")

        wanted = {self.exe.name, *WANTED_FILES}
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            for member in zf.namelist():
                name = Path(member).name  # drop any directories from the archive
                if name not in wanted:
                    continue
                target = self.dir / name
                tmp = target.with_suffix(target.suffix + ".new")
                tmp.write_bytes(zf.read(member))
                if name == self.exe.name and sys.platform != "win32":
                    tmp.chmod(0o755)
                os.replace(tmp, target)
        if not self.installed():
            raise CoreError("в архиве не нашлось xray и geo-файлов")
        self._version = None
        self.logs.add("core", f"установлено: Xray {self.version() or '?'}")

    # ---- run ---------------------------------------------------------
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def _test_config(self, path: Path | None = None) -> None:
        res = subprocess.run(
            [str(self.exe), "run", "-test", "-c", str(path or self.config_path)],
            capture_output=True, text=True, timeout=60, cwd=self.dir, env=self._env(),
            **self._popen_kwargs(),
        )
        if res.returncode != 0:
            tail = (res.stdout + res.stderr).strip().splitlines()[-3:]
            raise CoreError("Xray отклонил конфиг: " + " | ".join(tail))

    def start(self, config: dict, wait_port: int) -> None:
        if self.running():
            raise CoreError("ядро уже запущено")
        if not self.installed():
            raise CoreError("ядро Xray не установлено (Settings → Install core)")
        for inbound in config["inbounds"]:
            if not port_is_free(inbound["port"]):
                raise CoreError(f"порт {inbound['port']} занят другой программой")

        self.config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        t0 = time.perf_counter()
        self._test_config()
        self.logs.add("core", f"конфиг проверен за {time.perf_counter() - t0:.1f} с")

        self.proc = subprocess.Popen(
            [str(self.exe), "run", "-c", str(self.config_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            cwd=self.dir, env=self._env(), text=True, encoding="utf-8", errors="replace",
            bufsize=1, **self._popen_kwargs(),
        )
        threading.Thread(target=self._pump, args=(self.proc,), daemon=True).start()

        t1 = time.perf_counter()
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                tail = " | ".join(self.logs.tail(3))
                self.proc = None
                raise CoreError(f"Xray сразу завершился: {tail}")
            if port_is_open(wait_port):
                self.logs.add("core", f"порт открылся за {time.perf_counter() - t1:.1f} с")
                return
            time.sleep(0.15)
        self.stop()
        raise CoreError(f"Xray не начал слушать порт за {START_TIMEOUT} секунд")

    def config_ok(self, config: dict) -> bool:
        """Would Xray accept this config? (used to find the one broken server in a batch)"""
        path = self.dir / "probe-check.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        try:
            self._test_config(path)
        except (CoreError, OSError, subprocess.SubprocessError):
            return False
        return True

    def run_probe(self, config: dict, wait_port: int) -> subprocess.Popen:
        """Start a second, short-lived Xray next to the main one. Caller must stop it."""
        if not self.installed():
            raise CoreError("ядро Xray не установлено")
        path = self.dir / "probe.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        self._test_config(path)
        proc = subprocess.Popen(
            [str(self.exe), "run", "-c", str(path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
            cwd=self.dir, env=self._env(), **self._popen_kwargs(),
        )
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if proc.poll() is not None:
                raise CoreError("проверочный Xray сразу завершился")
            if port_is_open(wait_port):
                return proc
            time.sleep(0.1)
        proc.kill()
        raise CoreError("проверочный Xray не запустился вовремя")

    def _pump(self, proc: subprocess.Popen) -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            if line.strip():
                self.logs.add("xray", line)

    def stop(self) -> None:
        proc, self.proc = self.proc, None
        if proc is None or proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
