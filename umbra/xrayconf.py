"""Build an Xray-core JSON config from a parsed VlessLink.

Layout of the generated config:

    inbounds : socks  127.0.0.1:<socks_port>   (apps that speak SOCKS5)
               http   127.0.0.1:<http_port>    (Windows system proxy uses this)
    outbounds: proxy  - the VLESS server (first = default route)
               direct - freedom
    routing  : see build_routing()
"""
from __future__ import annotations

import ipaddress

from .links import ProxyLink

MODES = {
    "global": "Весь трафик через прокси (кроме локальной сети)",
    "bypass_ru": "Сайты .ru/.su/.рф и IP России — напрямую, остальное через прокси",
}
LOG_LEVELS = ("debug", "info", "warning", "error", "none")

# Ready-made rule sets. The geosite categories were checked against the
# geosite.dat that ships with Xray 26.3.27 (xray run -test).
PRESETS = {
    "ads_block": {
        "title": "Блокировать рекламу и трекеры",
        "rules": [{"domain": ["geosite:category-ads-all"], "outboundTag": "block"}],
    },
    "ru_direct": {
        "title": "Российские сервисы напрямую: банки, госуслуги, Яндекс, VK, маркетплейсы",
        "rules": [{"domain": ["geosite:category-gov-ru", "geosite:category-bank-ru",
                              "geosite:category-ru", "geosite:yandex", "geosite:vk",
                              "geosite:mailru", "geosite:ozon", "geosite:wildberries"],
                   "outboundTag": "direct"}],
    },
    "torrents_direct": {
        "title": "Торренты напрямую, мимо сервера",
        "rules": [{"protocol": ["bittorrent"], "outboundTag": "direct"}],
    },
}

_DOMAIN_PREFIXES = ("domain:", "full:", "regexp:", "keyword:", "geosite:", "ext:")


def split_user_rules(entries: list[str]) -> tuple[list[str], list[str]]:
    """Split user-written 'direct' entries into (domain rules, ip rules).

    "example.com"      -> domain:example.com
    "full:a.b.com"     -> kept as is
    "10.1.0.0/16"      -> ip rule
    "geoip:cn"         -> ip rule
    """
    domains: list[str] = []
    ips: list[str] = []
    for raw in entries:
        item = raw.strip().lower()
        if not item or item.startswith("#"):
            continue
        if item.startswith("geoip:"):
            ips.append(item)
            continue
        if item.startswith(_DOMAIN_PREFIXES):
            domains.append(item)
            continue
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError:
            domains.append("domain:" + item)
        else:
            ips.append(item)
    return domains, ips


def build_routing(mode: str, direct_entries: list[str], proxy_entries: list[str] | None = None,
                  presets: list[str] | None = None) -> dict:
    if mode not in MODES:
        raise ValueError(f"неизвестный режим: {mode}")

    rules: list[dict] = []
    # "Always through the tunnel" goes first: it must win over .ru / geoip rules.
    forced_domains, forced_ips = split_user_rules(proxy_entries or [])
    if forced_domains:
        rules.append({"type": "field", "domain": forced_domains, "outboundTag": "proxy"})
    if forced_ips:
        rules.append({"type": "field", "ip": forced_ips, "outboundTag": "proxy"})

    user_domains, user_ips = split_user_rules(direct_entries)
    if user_domains:
        rules.append({"type": "field", "domain": user_domains, "outboundTag": "direct"})
    if user_ips:
        rules.append({"type": "field", "ip": user_ips, "outboundTag": "direct"})

    # Ready-made sets come after the user's own rules, so those always win.
    for name in presets or []:
        if name not in PRESETS:
            raise ValueError(f"неизвестный набор правил: {name}")
        for rule in PRESETS[name]["rules"]:
            rules.append({"type": "field", **rule})

    # LAN / loopback never goes through the proxy.
    rules.append({"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"})

    if mode == "bypass_ru":
        rules.append({
            "type": "field",
            "domain": ["domain:ru", "domain:su", "domain:xn--p1ai"],
            "outboundTag": "direct",
        })
        rules.append({"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"})

    # IPIfNonMatch: if no domain rule matched, resolve the name and try the
    # IP rules (needed for geoip:ru). In "global" mode there is nothing to
    # match by IP beyond private ranges, so skip the extra DNS lookups.
    needs_ip = mode == "bypass_ru" or bool(user_ips) or bool(forced_ips)
    strategy = "IPIfNonMatch" if needs_ip else "AsIs"
    return {"domainStrategy": strategy, "rules": rules}


def _stream_settings(v: ProxyLink) -> dict:
    s: dict = {"network": v.network, "security": v.security}

    if v.network == "ws":
        ws: dict = {"path": v.path or "/"}
        if v.host_header:
            ws["headers"] = {"Host": v.host_header}
        s["wsSettings"] = ws
    elif v.network == "grpc":
        s["grpcSettings"] = {
            "serviceName": v.service_name,
            "multiMode": v.mode == "multi",
        }
    elif v.network == "xhttp":
        x: dict = {"path": v.path or "/", "mode": v.mode or "auto"}
        if v.host_header:
            x["host"] = v.host_header
        if v.extra:
            x["extra"] = v.extra
        s["xhttpSettings"] = x
    elif v.network == "httpupgrade":
        h: dict = {"path": v.path or "/"}
        if v.host_header:
            h["host"] = v.host_header
        s["httpupgradeSettings"] = h

    server_name = v.sni or v.host_header or v.host
    if v.security == "tls":
        tls: dict = {"serverName": server_name, "fingerprint": v.fp or "chrome"}
        if v.alpn:
            tls["alpn"] = v.alpn
        s["tlsSettings"] = tls
    elif v.security == "reality":
        s["realitySettings"] = {
            "serverName": server_name,
            "fingerprint": v.fp or "chrome",
            "publicKey": v.pbk,
            "shortId": v.sid,
            "spiderX": v.spx,
        }
    return s


def _outbound(v: ProxyLink, tag: str = "proxy") -> dict:
    """The outbound that talks to the remote server, for any supported protocol."""
    if v.protocol == "vless":
        user: dict = {"id": v.uuid, "encryption": v.encryption}
        if v.flow:
            user["flow"] = v.flow
        settings: dict = {"vnext": [{"address": v.host, "port": v.port, "users": [user]}]}
    elif v.protocol == "vmess":
        settings = {"vnext": [{"address": v.host, "port": v.port,
                               "users": [{"id": v.uuid, "security": v.method or "auto"}]}]}
    elif v.protocol == "trojan":
        server: dict = {"address": v.host, "port": v.port, "password": v.password}
        if v.flow:
            server["flow"] = v.flow
        settings = {"servers": [server]}
    elif v.protocol == "shadowsocks":
        settings = {"servers": [{"address": v.host, "port": v.port,
                                 "method": v.method, "password": v.password}]}
    else:
        raise ValueError(f"неизвестный протокол: {v.protocol}")
    return {"tag": tag, "protocol": v.protocol, "settings": settings,
            "streamSettings": _stream_settings(v)}


def build_config(
    v: ProxyLink,
    mode: str = "bypass_ru",
    socks_port: int = 10808,
    http_port: int = 10809,
    loglevel: str = "warning",
    direct_entries: list[str] | None = None,
    proxy_entries: list[str] | None = None,
    metrics_port: int | None = None,
    show_connections: bool = False,
    presets: list[str] | None = None,
) -> dict:
    if loglevel not in LOG_LEVELS:
        raise ValueError(f"неизвестный loglevel: {loglevel}")

    sniffing = {
        "enabled": True,
        "destOverride": ["http", "tls"],
        # routeOnly: the sniffed domain is used for routing decisions only;
        # the connection still goes to the original destination address.
        "routeOnly": True,
    }
    log: dict = {"loglevel": loglevel}
    if not show_connections:
        log["access"] = "none"     # do not print every connection into the journal

    config: dict = {
        "log": log,
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": True, "auth": "noauth"},
                "sniffing": sniffing,
            },
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": http_port,
                "protocol": "http",
                "settings": {},
                "sniffing": sniffing,
            },
        ],
        "outbounds": [_outbound(v), {"tag": "direct", "protocol": "freedom"},
                      {"tag": "block", "protocol": "blackhole"}],
        "routing": build_routing(mode, direct_entries or [], proxy_entries or [], presets or []),
    }
    if metrics_port:
        # Traffic counters, read by the app from http://127.0.0.1:<port>/debug/vars
        config["stats"] = {}
        config["policy"] = {"system": {
            "statsInboundUplink": True, "statsInboundDownlink": True,
            "statsOutboundUplink": True, "statsOutboundDownlink": True,
        }}
        config["metrics"] = {"tag": "metrics", "listen": f"127.0.0.1:{metrics_port}"}
    return config


def build_probe_config(servers: list[tuple[str, ProxyLink, int]]) -> dict:
    """One throw-away Xray that exposes every server on its own local HTTP port.

    servers: [(id, link, local_port)]. A request sent to local_port leaves
    through that server only, so we can time each tunnel separately without
    touching the user's live connection.
    """
    inbounds, outbounds, rules = [], [], []
    for sid, link, port in servers:
        inbounds.append({"tag": f"in-{sid}", "listen": "127.0.0.1", "port": port,
                         "protocol": "http", "settings": {}})
        outbounds.append(_outbound(link, tag=f"out-{sid}"))
        rules.append({"type": "field", "inboundTag": [f"in-{sid}"], "outboundTag": f"out-{sid}"})
    return {
        "log": {"loglevel": "none", "access": "none"},
        "inbounds": inbounds,
        "outbounds": outbounds + [{"tag": "block", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
