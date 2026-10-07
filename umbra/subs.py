"""Subscription import: download a URL, decode, return links + metadata."""
from __future__ import annotations

import base64
import binascii
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

MAX_BYTES = 2 * 1024 * 1024
USER_AGENT = "Umbra/0.2"


@dataclass
class SubResult:
    lines: list[str]
    title: str = ""                              # "profile-title" header
    info: dict = field(default_factory=dict)     # upload/download/total (bytes), expire (unix time)


def decode_subscription(body: bytes) -> list[str]:
    """Return all non-empty lines of a subscription body.

    Panels return either plain text with one link per line or the same text
    base64-encoded (standard or url-safe alphabet, padding often stripped).
    """
    text = body.decode("utf-8", errors="replace").strip()
    if "://" not in text:
        compact = "".join(text.split()).replace("-", "+").replace("_", "/")  # url-safe -> standard
        padded = compact + "=" * (-len(compact) % 4)
        try:
            text = base64.b64decode(padded, validate=True).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            text = ""
        if "://" not in text:
            raise ValueError("подписка не похожа ни на список ссылок, ни на base64")
    return [line.strip() for line in text.splitlines() if line.strip()]


def parse_userinfo(header: str) -> dict:
    """'upload=1; download=2; total=3; expire=1700000000' -> dict of ints."""
    info: dict = {}
    for part in (header or "").split(";"):
        key, _, value = part.strip().partition("=")
        if key in ("upload", "download", "total", "expire"):
            try:
                info[key] = int(float(value))
            except ValueError:
                pass
    return info


def parse_title(header: str) -> str:
    """profile-title is plain text, URL-encoded text or 'base64:<...>'."""
    header = (header or "").strip()
    if header.lower().startswith("base64:"):
        raw = header[7:].strip()
        try:
            header = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            return ""
    return unquote(header).strip()[:80]


def fetch_subscription(url: str, timeout: float = 15.0) -> SubResult:
    scheme = urlsplit(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("адрес подписки должен начинаться с http:// или https://")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read(MAX_BYTES + 1)
        title = parse_title(resp.headers.get("profile-title", ""))
        info = parse_userinfo(resp.headers.get("subscription-userinfo", ""))
    if len(body) > MAX_BYTES:
        raise ValueError("ответ подписки слишком большой (больше 2 МБ)")
    lines = decode_subscription(body)
    if any(line.lower().startswith("happ://") for line in lines):
        raise ValueError(
            "подписка зашифрована (happ://crypt…), такие клиент не расшифровывает. "
            "Возьми у панели обычную ссылку подписки"
        )
    return SubResult(lines=lines, title=title, info=info)
