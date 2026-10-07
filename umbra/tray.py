"""System tray icon for Windows, written directly against the Win32 API (ctypes).

Why by hand: the project has no third-party dependencies, and a tray icon needs
only a hidden window, Shell_NotifyIconW and a popup menu.

How it works:
  * a dedicated thread creates a hidden window and runs its message loop;
  * the icon sends WM_TRAY to that window on clicks;
  * right click builds the popup menu from the current state;
  * menu actions call back into the application on worker threads, so a slow
    "connect" never freezes the menu.

Every Win32 function gets explicit argtypes/restype: on 64-bit Windows handles
are 8 bytes, and ctypes' default "int" return type would silently cut them.
"""
from __future__ import annotations

import ctypes
import logging
import sys
import threading
from pathlib import Path
from typing import Callable

log = logging.getLogger("umbra.tray")
IS_WINDOWS = sys.platform == "win32"

# ---- Win32 constants -------------------------------------------------
WM_DESTROY, WM_CLOSE, WM_NULL, WM_APP = 0x0002, 0x0010, 0x0000, 0x8000
WM_LBUTTONUP, WM_LBUTTONDBLCLK, WM_RBUTTONUP, WM_CONTEXTMENU = 0x0202, 0x0203, 0x0205, 0x007B
WM_TRAY = WM_APP + 1          # our private "something happened on the icon" message
NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO = 0x01, 0x02, 0x04, 0x10
NIIF_INFO = 0x01
MF_STRING, MF_GRAYED, MF_SEPARATOR = 0x0000, 0x0001, 0x0800
TPM_RIGHTBUTTON, TPM_NONOTIFY, TPM_RETURNCMD = 0x0002, 0x0080, 0x0100
IMAGE_ICON, LR_LOADFROMFILE, LR_DEFAULTSIZE = 1, 0x0010, 0x0040
IDI_APPLICATION = 32512
CMD_OPEN, CMD_TOGGLE, CMD_QUIT = 1, 2, 3

# ---- Win32 types (fixed widths, so the layout can be checked on any OS) ----
HANDLE = ctypes.c_void_p
UINT = ctypes.c_uint32
DWORD = ctypes.c_uint32
WPARAM = ctypes.c_size_t
LPARAM = ctypes.c_ssize_t
LRESULT = ctypes.c_ssize_t
WCHAR = ctypes.c_wchar          # 2 bytes on Windows


def make_notify_struct(wchar=WCHAR):
    """NOTIFYICONDATAW. `wchar` is a parameter only so tests can check the size."""

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16),
                    ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_uint8 * 8)]

    class NOTIFYICONDATAW(ctypes.Structure):
        _fields_ = [
            ("cbSize", DWORD),
            ("hWnd", HANDLE),
            ("uID", UINT),
            ("uFlags", UINT),
            ("uCallbackMessage", UINT),
            ("hIcon", HANDLE),
            ("szTip", wchar * 128),
            ("dwState", DWORD),
            ("dwStateMask", DWORD),
            ("szInfo", wchar * 256),
            ("uVersion", UINT),            # union with uTimeout
            ("szInfoTitle", wchar * 64),
            ("dwInfoFlags", DWORD),
            ("guidItem", GUID),
            ("hBalloonIcon", HANDLE),
        ]

    return NOTIFYICONDATAW


NOTIFYICONDATAW = make_notify_struct()


class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_int32), ("y", ctypes.c_int32)]


class MSG(ctypes.Structure):
    _fields_ = [("hwnd", HANDLE), ("message", UINT), ("wParam", WPARAM), ("lParam", LPARAM),
                ("time", DWORD), ("pt", POINT), ("lPrivate", DWORD)]


if IS_WINDOWS:
    WNDPROC = ctypes.WINFUNCTYPE(LRESULT, HANDLE, UINT, WPARAM, LPARAM)

    class WNDCLASSW(ctypes.Structure):
        _fields_ = [
            ("style", UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int32),
            ("cbWndExtra", ctypes.c_int32), ("hInstance", HANDLE), ("hIcon", HANDLE),
            ("hCursor", HANDLE), ("hbrBackground", HANDLE),
            ("lpszMenuName", ctypes.c_wchar_p), ("lpszClassName", ctypes.c_wchar_p),
        ]

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    def _sig(func, restype, *argtypes):
        func.restype, func.argtypes = restype, list(argtypes)

    W, B, I = ctypes.c_wchar_p, ctypes.c_int32, ctypes.c_int32      # noqa: E741
    _sig(kernel32.GetModuleHandleW, HANDLE, W)
    _sig(user32.RegisterClassW, ctypes.c_uint16, ctypes.POINTER(WNDCLASSW))
    _sig(user32.CreateWindowExW, HANDLE, DWORD, W, W, DWORD, I, I, I, I, HANDLE, HANDLE, HANDLE, HANDLE)
    _sig(user32.DefWindowProcW, LRESULT, HANDLE, UINT, WPARAM, LPARAM)
    _sig(user32.DestroyWindow, B, HANDLE)
    _sig(user32.PostMessageW, B, HANDLE, UINT, WPARAM, LPARAM)
    _sig(user32.PostQuitMessage, None, I)
    _sig(user32.GetMessageW, B, ctypes.POINTER(MSG), HANDLE, UINT, UINT)
    _sig(user32.TranslateMessage, B, ctypes.POINTER(MSG))
    _sig(user32.DispatchMessageW, LRESULT, ctypes.POINTER(MSG))
    _sig(user32.RegisterWindowMessageW, UINT, W)
    _sig(user32.LoadImageW, HANDLE, HANDLE, W, UINT, I, I, UINT)
    _sig(user32.LoadIconW, HANDLE, HANDLE, HANDLE)
    _sig(user32.CreatePopupMenu, HANDLE)
    _sig(user32.AppendMenuW, B, HANDLE, UINT, ctypes.c_size_t, W)
    _sig(user32.DestroyMenu, B, HANDLE)
    _sig(user32.GetCursorPos, B, ctypes.POINTER(POINT))
    _sig(user32.SetForegroundWindow, B, HANDLE)
    _sig(user32.TrackPopupMenu, B, HANDLE, UINT, I, I, I, HANDLE, HANDLE)
    _sig(user32.FindWindowW, HANDLE, W, W)
    _sig(user32.ShowWindow, B, HANDLE, I)
    _sig(user32.IsIconic, B, HANDLE)
    _sig(shell32.Shell_NotifyIconW, B, DWORD, ctypes.POINTER(NOTIFYICONDATAW))
    _sig(shell32.ExtractIconW, HANDLE, HANDLE, W, UINT)


def focus_window(title: str) -> bool:
    """Bring an already open window with this exact title to the front."""
    if not IS_WINDOWS:
        return False
    hwnd = user32.FindWindowW(None, title)
    if not hwnd:
        return False
    if user32.IsIconic(hwnd):
        user32.ShowWindow(hwnd, 9)      # SW_RESTORE
    user32.SetForegroundWindow(hwnd)
    return True


class Tray:
    """Tray icon with a three-item menu.

    get_state() -> {"connected": bool, "busy": bool, "can_connect": bool, "tip": str}
    on_open / on_toggle / on_quit are called on worker threads.
    """

    def __init__(self, get_state: Callable[[], dict], on_open: Callable[[], None],
                 on_toggle: Callable[[], None], on_quit: Callable[[], None]):
        self.get_state, self.on_open, self.on_toggle, self.on_quit = get_state, on_open, on_toggle, on_quit
        self.hwnd = None
        self.hicon = None
        self._tip = "Umbra"
        self._ready = threading.Event()
        self._ok = False
        self._thread: threading.Thread | None = None
        self._wndproc = None            # keep a reference: Windows calls it for the window's lifetime
        self._taskbar_created = 0

    # ---- public API (any thread) -----------------------------------------
    def start(self, timeout: float = 5.0) -> bool:
        """Create the icon. False means "no tray on this system", never an exception."""
        if not IS_WINDOWS:
            return False
        self._thread = threading.Thread(target=self._run, name="tray", daemon=True)
        self._thread.start()
        self._ready.wait(timeout)
        return self._ok

    def set_tip(self, text: str) -> None:
        text = text[:127]
        if not self._ok or text == self._tip:
            return
        self._tip = text
        self._notify(NIM_MODIFY, NIF_TIP)

    def balloon(self, title: str, text: str) -> None:
        """A short notification next to the icon."""
        if not self._ok:
            return
        data = self._data(NIF_INFO)
        data.szInfoTitle = title[:63]
        data.szInfo = text[:255]
        data.dwInfoFlags = NIIF_INFO
        shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(data))

    def stop(self) -> None:
        if self._ok and self.hwnd:
            user32.PostMessageW(self.hwnd, WM_CLOSE, 0, 0)
            if self._thread:
                self._thread.join(timeout=2)

    # ---- internals (tray thread) -------------------------------------------
    def _data(self, flags: int):
        data = NOTIFYICONDATAW()
        data.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        data.hWnd = self.hwnd
        data.uID = 1
        data.uFlags = flags
        data.uCallbackMessage = WM_TRAY
        data.hIcon = self.hicon
        data.szTip = self._tip
        return data

    def _notify(self, action: int, flags: int) -> bool:
        return bool(shell32.Shell_NotifyIconW(action, ctypes.byref(self._data(flags))))

    def _load_icon(self):
        if getattr(sys, "frozen", False):
            icon = shell32.ExtractIconW(None, sys.executable, 0)     # the .exe's own icon
            if icon and icon > 1:
                return icon
        path = Path(__file__).resolve().parent.parent / "assets" / "icon.ico"
        if path.is_file():
            icon = user32.LoadImageW(None, str(path), IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE)
            if icon:
                return icon
        return user32.LoadIconW(None, IDI_APPLICATION)               # generic Windows icon

    def _run(self) -> None:
        try:
            hinst = kernel32.GetModuleHandleW(None)
            self._wndproc = WNDPROC(self._on_message)
            cls = WNDCLASSW()
            cls.lpfnWndProc = self._wndproc
            cls.hInstance = hinst
            cls.lpszClassName = "UmbraTray"
            if not user32.RegisterClassW(ctypes.byref(cls)):
                raise ctypes.WinError(ctypes.get_last_error())
            # An ordinary hidden window (not a message-only one): only those
            # receive "TaskbarCreated" when Explorer restarts.
            self.hwnd = user32.CreateWindowExW(0, cls.lpszClassName, "Umbra tray", 0,
                                               0, 0, 0, 0, None, None, hinst, None)
            if not self.hwnd:
                raise ctypes.WinError(ctypes.get_last_error())
            self.hicon = self._load_icon()
            self._taskbar_created = user32.RegisterWindowMessageW("TaskbarCreated")
            if not self._notify(NIM_ADD, NIF_MESSAGE | NIF_ICON | NIF_TIP):
                raise OSError("Shell_NotifyIconW(NIM_ADD) failed")
            self._ok = True
        except Exception:  # noqa: BLE001 - the app must work without a tray
            log.exception("tray icon could not be created")
            self._ready.set()
            return
        self._ready.set()

        msg = MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
        self._ok = False

    def _on_message(self, hwnd, message, wparam, lparam):
        try:
            if message == WM_TRAY:
                event = lparam & 0xFFFF
                if event in (WM_LBUTTONUP, WM_LBUTTONDBLCLK):
                    self._async(self.on_open)
                elif event in (WM_RBUTTONUP, WM_CONTEXTMENU):
                    self._show_menu()
                return 0
            if message == self._taskbar_created and self._taskbar_created:
                self._notify(NIM_ADD, NIF_MESSAGE | NIF_ICON | NIF_TIP)   # Explorer restarted
                return 0
            if message == WM_CLOSE:
                user32.DestroyWindow(hwnd)
                return 0
            if message == WM_DESTROY:
                self._notify(NIM_DELETE, 0)
                user32.PostQuitMessage(0)
                return 0
        except Exception:  # noqa: BLE001 - never let an exception escape into Windows
            log.exception("tray message %s", message)
        return user32.DefWindowProcW(hwnd, message, wparam, lparam)

    def _show_menu(self) -> None:
        state = self.get_state()
        menu = user32.CreatePopupMenu()
        user32.AppendMenuW(menu, MF_STRING, CMD_OPEN, "Открыть окно")
        if state.get("busy"):
            user32.AppendMenuW(menu, MF_STRING | MF_GRAYED, CMD_TOGGLE, "Подключаюсь…")
        elif state.get("connected"):
            user32.AppendMenuW(menu, MF_STRING, CMD_TOGGLE, "Отключить")
        else:
            flags = MF_STRING if state.get("can_connect") else MF_STRING | MF_GRAYED
            user32.AppendMenuW(menu, flags, CMD_TOGGLE, "Подключить")
        user32.AppendMenuW(menu, MF_SEPARATOR, 0, None)
        user32.AppendMenuW(menu, MF_STRING, CMD_QUIT, "Выйти")

        point = POINT()
        user32.GetCursorPos(ctypes.byref(point))
        user32.SetForegroundWindow(self.hwnd)       # otherwise the menu does not close on click-away
        cmd = user32.TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_NONOTIFY | TPM_RETURNCMD,
                                    point.x, point.y, 0, self.hwnd, None)
        user32.PostMessageW(self.hwnd, WM_NULL, 0, 0)
        user32.DestroyMenu(menu)
        if cmd == CMD_OPEN:
            self._async(self.on_open)
        elif cmd == CMD_TOGGLE:
            self._async(self.on_toggle)
        elif cmd == CMD_QUIT:
            self._async(self.on_quit)

    @staticmethod
    def _async(func: Callable[[], None]) -> None:
        def run():
            try:
                func()
            except Exception:  # noqa: BLE001
                log.exception("tray action")
        threading.Thread(target=run, daemon=True).start()
