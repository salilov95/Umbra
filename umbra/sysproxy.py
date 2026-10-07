"""Windows system proxy (Internet Settings in HKCU).

Safety model - the user's rule is "no change without a backup and a way back":
  * enable() returns a dict with the previous values; the caller persists it
    BEFORE the app exits, so restore() can undo exactly what we changed;
  * restore() puts back only the three values we touched;
  * on non-Windows systems everything is a no-op (used by tests).
"""
from __future__ import annotations

import sys

IS_WINDOWS = sys.platform == "win32"
_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_VALUES = ("ProxyEnable", "ProxyServer", "ProxyOverride")
_BYPASS = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2*;172.30.*;172.31.*;192.168.*;<local>"

if IS_WINDOWS:
    import ctypes
    import winreg


def _notify() -> None:
    """Tell WinINet that settings changed so running apps pick it up."""
    if not IS_WINDOWS:
        return
    wininet = ctypes.windll.wininet
    wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
    wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH


def read_current() -> dict:
    """Current values; a missing value is stored as None."""
    if not IS_WINDOWS:
        return {name: None for name in _VALUES}
    result: dict = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY, 0, winreg.KEY_READ) as key:
        for name in _VALUES:
            try:
                value, kind = winreg.QueryValueEx(key, name)
                result[name] = [value, kind]
            except FileNotFoundError:
                result[name] = None
    return result


def enable(http_port: int) -> dict:
    """Point the system proxy at 127.0.0.1:<http_port>. Returns the backup."""
    backup = read_current()
    if not IS_WINDOWS:
        return backup
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{http_port}")
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, _BYPASS)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    _notify()
    return backup


def restore(backup: dict | None) -> None:
    """Put back the values saved by enable(). With no backup: just switch off."""
    if not IS_WINDOWS:
        return
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY, 0, winreg.KEY_SET_VALUE) as key:
        if not backup:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        else:
            for name in _VALUES:
                saved = backup.get(name)
                if saved is None:
                    try:
                        winreg.DeleteValue(key, name)
                    except FileNotFoundError:
                        pass
                else:
                    value, kind = saved
                    winreg.SetValueEx(key, name, 0, kind, value)
    _notify()
