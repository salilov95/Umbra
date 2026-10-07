"""Start with Windows (HKCU\\...\\Run). Only offered for the .exe build:
a path to a Python script inside a project folder is too fragile to register.
"""
from __future__ import annotations

import sys

IS_WINDOWS = sys.platform == "win32"
_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_NAME = "Umbra"

if IS_WINDOWS:
    import winreg


_LEGACY_NAME = "Vless" + "Client"    # registry value used before 0.6.0


def drop_legacy() -> None:
    """Remove the old name from "start with Windows"; keep the feature on under the new one."""
    if not IS_WINDOWS:
        return
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY, 0,
                            winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
            try:
                winreg.QueryValueEx(key, _LEGACY_NAME)
            except FileNotFoundError:
                return
            winreg.DeleteValue(key, _LEGACY_NAME)
            if available():
                winreg.SetValueEx(key, _NAME, 0, winreg.REG_SZ, _command())
    except OSError:
        pass


def available() -> bool:
    return IS_WINDOWS and bool(getattr(sys, "frozen", False))


def _command() -> str:
    return f'"{sys.executable}" --tray'      # start quietly in the tray


def enabled() -> bool:
    if not available():
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, _NAME)
    except OSError:
        return False
    return value == _command()


def set_enabled(on: bool) -> None:
    if not available():
        raise OSError("автозапуск доступен только в собранном Umbra.exe")
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY, 0, winreg.KEY_SET_VALUE) as key:
        if on:
            winreg.SetValueEx(key, _NAME, 0, winreg.REG_SZ, _command())
        else:
            try:
                winreg.DeleteValue(key, _NAME)
            except FileNotFoundError:
                pass
