#!/usr/bin/env python3
"""Раздача .ovpn профилей с эмуляцией импорта OpenVPN Access Server.

Пользователь вводит в OpenVPN Connect адрес сервера, логин и одноразовый пароль.
Запасной путь - страница со ссылкой для браузера. Только stdlib.
HTTP за своим reverse proxy или HTTPS на готовых PEM (OVPN_DOMAIN / OVPN_CERT + OVPN_KEY).
"""
import argparse
import base64
import html
import ipaddress
import json
import os
import re
import secrets
import signal
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit

BASE_DIR = Path(__file__).resolve().parent
PROFILES_DIR = Path(os.environ.get("OVPN_PROFILES_DIR", BASE_DIR / "profiles"))
DB_PATH = Path(os.environ.get("OVPN_DATA_DIR", BASE_DIR)) / "tokens.json"
OVPN_MIME = "application/x-openvpn-profile"
# эндпоинты OpenVPN Access Server: Basic auth (Import Profile - URL в Connect) и токен-ссылки
REST_AUTH_ENDPOINTS = {"GetUserlogin", "GetAutologin", "GetGeneric"}
REST_ENDPOINTS = REST_AUTH_ENDPOINTS | {"GetProfileViaToken"}
# HTTPS: OVPN_DOMAIN берет сертификат certbot из /etc/letsencrypt/live/<домен>/,
# OVPN_CERT/OVPN_KEY - любые PEM. Ничего не задано - голый HTTP за своим прокси.
DOMAIN = os.environ.get("OVPN_DOMAIN", "").strip()
LE_LIVE = os.environ.get("OVPN_LE_LIVE", "/etc/letsencrypt/live")
TLS_CERT = os.environ.get("OVPN_CERT") or (f"{LE_LIVE}/{DOMAIN}/fullchain.pem" if DOMAIN else "")
TLS_KEY = os.environ.get("OVPN_KEY") or (f"{LE_LIVE}/{DOMAIN}/privkey.pem" if DOMAIN else "")
CERT_CHECK_INTERVAL = 3600  # как часто смотреть, не продлил ли certbot сертификат
# адреса прокси, которым верим X-Real-IP / X-Forwarded-For
TRUSTED_PROXIES = [ipaddress.ip_network(n.strip(), strict=False)
                   for n in os.environ.get("OVPN_TRUSTED_PROXIES", "").split(",") if n.strip()]
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # без 0/O, 1/I
CODE_LEN = 10  # ~50 бит
FAIL_WINDOW, FAIL_MAX = 900, 10  # не больше 10 неверных паролей с IP за 15 минут

_lock = threading.Lock()
_fails = {}


# ---------- хранилище токенов ----------

def load_db():
    if not DB_PATH.exists():
        return {}
    with DB_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def save_db(db):
    tmp = DB_PATH.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    os.replace(tmp, DB_PATH)


def resolve_profile(name):
    """Возвращает путь к профилю внутри PROFILES_DIR или None (защита от traversal)."""
    if not name or "/" in name or "\\" in name or not name.endswith(".ovpn"):
        return None
    path = (PROFILES_DIR / name).resolve()
    if path.parent != PROFILES_DIR.resolve() or not path.is_file():
        return None
    return path


def token_state(entry):
    """None если токен годен, иначе причина отказа."""
    if entry.get("revoked"):
        return "отозвана"
    if entry["expires"] and time.time() > entry["expires"]:
        return "истекла"
    if entry["max_downloads"] and entry["downloads"] >= entry["max_downloads"]:
        return "исчерпана"
    return None


def connect_url(base_url):
    """URL для Import Profile в Connect: только схема и хост, путь Connect все равно отбрасывает."""
    s = urlsplit(base_url)
    return f"{s.scheme}://{s.netloc}"


def with_profile_name(data, filename):
    """Имя профиля в Connect: "<хост из первой remote> [<имя файла>]", без remote - имя файла.

    Метаданные - комментарии "# OVPN_ACCESS_SERVER_<KEY>=<value>" (openvpn3: cliopthelper.hpp).
    """
    m = re.search(rb"^[ \t]*remote[ \t]+([^\s#;]+)", data, re.M)
    stem = Path(filename).stem
    name = f"{m.group(1).decode('utf-8', 'replace')} [{stem}]" if m else stem
    name = re.sub(r"[\x00-\x1f\x7f]", "", name)
    meta = b"".join(f"# OVPN_ACCESS_SERVER_{key}={name}\n".encode()
                    for key in ("PROFILE", "FRIENDLY_NAME")
                    if f"OVPN_ACCESS_SERVER_{key}=".encode() not in data)
    return meta + data


def new_code():
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LEN))


def find_by_credentials(db, user, code, token=None):
    """Активная запись по логину и одноразовому паролю, если задан token - только среди него.

    Регистр не важен: телефон любит ставить заглавную первую букву.
    """
    user, code = user.strip().lower(), code.strip().upper().encode()
    if token:
        candidates = [db[token]] if token in db else []
    else:
        candidates = db.values()
    for entry in candidates:
        if (entry.get("code") and entry.get("user", "").lower() == user
                and secrets.compare_digest(entry["code"].encode(), code)
                and token_state(entry) is None):
            return entry
    return None


def too_many_fails(ip):
    now = time.time()
    with _lock:
        recent = [t for t in _fails.get(ip, ()) if now - t < FAIL_WINDOW]
        if recent:
            _fails[ip] = recent
        else:
            _fails.pop(ip, None)
        return len(recent) >= FAIL_MAX


# ---------- QR: byte mode, уровень коррекции M, версии 1-10 (до 213 байт) ----------

# версия: (байт коррекции на блок, [(число блоков, байт данных в блоке), ...])
QR_M = {1: (10, [(1, 16)]), 2: (16, [(1, 28)]), 3: (26, [(1, 44)]), 4: (18, [(2, 32)]),
        5: (24, [(2, 43)]), 6: (16, [(4, 27)]), 7: (18, [(4, 31)]), 8: (22, [(2, 38), (2, 39)]),
        9: (22, [(3, 36), (2, 37)]), 10: (26, [(4, 43), (1, 44)])}
QR_ALIGN = {2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
            7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]}
QR_MASKS = [lambda x, y: (x + y) % 2 == 0, lambda x, y: y % 2 == 0,
            lambda x, y: x % 3 == 0, lambda x, y: (x + y) % 3 == 0,
            lambda x, y: (x // 3 + y // 2) % 2 == 0, lambda x, y: x * y % 2 + x * y % 3 == 0,
            lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0, lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0]


def _gf_tables():
    exp, log = [0] * 512, [0] * 256
    x = 1
    for i in range(255):
        exp[i], log[x] = x, i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    exp[255:] = exp[:257]
    return exp, log


_GF_EXP, _GF_LOG = _gf_tables()


def _gf_mul(a, b):
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]] if a and b else 0


def _rs_ec(data, n):
    """Байты коррекции Рида-Соломона: остаток от деления на порождающий многочлен."""
    gen = [1]
    for i in range(n):
        nxt = gen + [0]
        for j, c in enumerate(gen):
            nxt[j + 1] ^= _gf_mul(c, _GF_EXP[i])
        gen = nxt
    res = list(data) + [0] * n
    for i in range(len(data)):
        if res[i]:
            coef = res[i]
            for j in range(1, len(gen)):
                res[i + j] ^= _gf_mul(gen[j], coef)
    return res[len(data):]


def _qr_penalty(g):
    n, score = len(g), 0
    finder = [True, False, True, True, True, False, True]
    for line in g + [list(col) for col in zip(*g)]:
        run = 1
        for i in range(1, n + 1):
            if i < n and line[i] == line[i - 1]:
                run += 1
                continue
            if run >= 5:
                score += run - 2
            run = 1
        p = [False] * 4 + line + [False] * 4
        for i in range(len(p) - 10):
            if ((p[i:i + 7] == finder and not any(p[i + 7:i + 11]))
                    or (p[i + 4:i + 11] == finder and not any(p[i:i + 4]))):
                score += 40
    for y in range(n - 1):
        for x in range(n - 1):
            if g[y][x] == g[y][x + 1] == g[y + 1][x] == g[y + 1][x + 1]:
                score += 3
    dark = sum(map(sum, g))
    return score + 10 * (abs(dark * 100 // (n * n) - 50) // 5)


def qr_matrix(text):
    """Матрица QR (list строк из bool, True - темный модуль). ValueError, если не влезает."""
    data = text.encode("utf-8")
    for ver, (ec_len, groups) in QR_M.items():
        cap = sum(cnt * size for cnt, size in groups)
        count_bits = 8 if ver < 10 else 16
        if 4 + count_bits + 8 * len(data) <= cap * 8:
            break
    else:
        raise ValueError(f"строка длиннее {cap - 3} байт не влезает в QR")

    bits = [0, 1, 0, 0] + [(len(data) >> i) & 1 for i in reversed(range(count_bits))]
    bits += [(b >> i) & 1 for b in data for i in reversed(range(8))]
    bits += [0] * min(4, cap * 8 - len(bits))
    bits += [0] * (-len(bits) % 8)
    words = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    words += [0xEC, 0x11] * ((cap - len(words)) // 2) + [0xEC] * ((cap - len(words)) % 2)

    blocks, k = [], 0
    for cnt, size in groups:
        for _ in range(cnt):
            blocks.append(words[k:k + size])
            k += size
    ecs = [_rs_ec(b, ec_len) for b in blocks]
    stream = [b[i] for i in range(max(map(len, blocks))) for b in blocks if i < len(b)]
    stream += [e[i] for i in range(ec_len) for e in ecs]

    n = 17 + 4 * ver
    grid = [[False] * n for _ in range(n)]
    func = [[False] * n for _ in range(n)]

    def put(g, x, y, v):
        g[y][x] = v
        func[y][x] = True

    def put_format(g, mask):
        val = mask  # биты уровня M - 00
        rem = val
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        fmt = (val << 10 | rem) ^ 0x5412
        bit = [(fmt >> i) & 1 == 1 for i in range(15)]
        for i in range(6):
            put(g, 8, i, bit[i])
        put(g, 8, 7, bit[6])
        put(g, 8, 8, bit[7])
        put(g, 7, 8, bit[8])
        for i in range(9, 15):
            put(g, 14 - i, 8, bit[i])
        for i in range(8):
            put(g, n - 1 - i, 8, bit[i])
        for i in range(8, 15):
            put(g, 8, n - 15 + i, bit[i])
        put(g, 8, n - 8, True)

    for i in range(n):
        put(grid, 6, i, i % 2 == 0)
        put(grid, i, 6, i % 2 == 0)
    for cx, cy in ((3, 3), (n - 4, 3), (3, n - 4)):
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                if 0 <= cx + dx < n and 0 <= cy + dy < n:
                    put(grid, cx + dx, cy + dy, max(abs(dx), abs(dy)) not in (2, 4))
    pos = QR_ALIGN.get(ver, [])
    for cy in pos:
        for cx in pos:
            if (cx, cy) in ((pos[0], pos[0]), (pos[0], pos[-1]), (pos[-1], pos[0])):
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    put(grid, cx + dx, cy + dy, max(abs(dx), abs(dy)) != 1)
    put_format(grid, 0)  # резервируем области формата
    if ver >= 7:
        rem = ver
        for _ in range(12):
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
        vbits = ver << 12 | rem
        for i in range(18):
            a, b = n - 11 + i % 3, i // 3
            put(grid, a, b, (vbits >> i) & 1 == 1)
            put(grid, b, a, (vbits >> i) & 1 == 1)

    # данные змейкой по парам столбцов снизу вверх и обратно
    i, total = 0, len(stream) * 8
    for right in range(n - 1, 0, -2):
        if right <= 6:
            right -= 1  # вертикальная линия синхронизации
        upward = ((right + 1) & 2) == 0
        for vert in range(n):
            y = n - 1 - vert if upward else vert
            for x in (right, right - 1):
                if not func[y][x] and i < total:
                    grid[y][x] = (stream[i >> 3] >> (7 - (i & 7))) & 1 == 1
                    i += 1

    best = None
    for mask, fn in enumerate(QR_MASKS):
        g = [[v ^ (not func[y][x] and fn(x, y)) for x, v in enumerate(row)] for y, row in enumerate(grid)]
        put_format(g, mask)
        score = _qr_penalty(g)
        if best is None or score < best[0]:
            best = (score, g)
    return best[1]


def qr_terminal(text, quiet=2):
    """QR полублоками: черное на белом явно через ANSI, чтобы читалось и на темной теме."""
    m = qr_matrix(text)
    n = len(m)

    def dark(x, y):
        return 0 <= x < n and 0 <= y < n and m[y][x]

    rows = []
    for y in range(-quiet, n + quiet, 2):
        line = "".join(" ▀▄█"[dark(x, y) | dark(x, y + 1) << 1] for x in range(-quiet, n + quiet))
        rows.append(f"\x1b[30;107m{line}\x1b[0m")
    return "\n".join(rows)


def qr_svg(text, quiet=4):
    m = qr_matrix(text)
    size = len(m) + 2 * quiet
    path = []
    for y, row in enumerate(m):
        x = 0
        while x < len(row):
            if row[x]:
                start = x
                while x < len(row) and row[x]:
                    x += 1
                path.append(f"M{start + quiet} {y + quiet}h{x - start}v1h{start - x}z")
            else:
                x += 1
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" shape-rendering="crispEdges" '
            f'role="img" aria-label="QR"><rect width="{size}" height="{size}" fill="#fff"/>'
            f'<path d="{"".join(path)}" fill="#000"/></svg>')


def print_qr(url):
    try:
        print(qr_terminal(url))
    except (ValueError, UnicodeEncodeError) as e:
        print(f"  (QR не выведен: {e})")


# ---------- HTTP ----------

PAGE = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>VPN профиль</title>
<style>
body{{font:17px -apple-system,system-ui,sans-serif;max-width:480px;margin:0 auto;padding:24px 16px;color:#222;background:#fafafa}}
a.btn{{display:block;text-align:center;padding:14px;margin:12px 0;border-radius:10px;
background:#ff7a00;color:#fff;text-decoration:none;font-weight:600}}
a.alt{{background:#e4e4e4;color:#222}}
ol{{padding-left:20px;line-height:1.5}} small{{color:#777}}
td{{padding:4px 8px 4px 0}} code{{font-size:18px;user-select:all;-webkit-user-select:all}}
.qr svg{{display:block;width:220px;height:220px;margin:8px 0}}
@media (prefers-color-scheme:dark){{body{{background:#111;color:#eee}}a.alt{{background:#333;color:#eee}}}}
</style></head><body>
<h2>Профиль {name}</h2>
<a class="btn" href="{download}">Скачать профиль</a>
<a class="btn alt" href="{deeplink}">Открыть в OpenVPN Connect</a>
<ol>
<li>Установите <b>OpenVPN Connect</b> (App Store / Google Play / openvpn.net).</li>
<li>iPhone: нажмите "Скачать профиль", затем откройте загрузку (значок стрелки в адресной строке Safari
или приложение Файлы &rarr; Загрузки), "Поделиться" &rarr; OpenVPN.</li>
<li>Android / ПК: скачайте файл и откройте его в OpenVPN Connect (Import Profile &rarr; File).</li>
</ol>
{app_import}
{qr}
<small>Ссылка действует до {expires}, осталось скачиваний: {left}.</small>
</body></html>"""

APP_IMPORT = """<h3>Или импорт прямо из приложения</h3>
<p>OpenVPN Connect &rarr; Import Profile &rarr; URL, вставьте:</p>
<table>
<tr><td>URL</td><td><code>{url}</code></td></tr>
<tr><td>Username</td><td><code>{user}</code></td></tr>
<tr><td>Password</td><td><code>{code}</code></td></tr>
</table>
<p><small>Пароль одноразовый, это не пароль VPN. После импорта он больше не нужен.</small></p>"""

ERROR_PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Ссылка недействительна</title></head>
<body style="font:17px system-ui,sans-serif;padding:24px 16px"><h2>Ссылка {reason}</h2>
<p>Запросите новую у администратора.</p></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "ovpn-sender"
    sys_version = ""
    base_url = ""
    timeout = 30  # и для TLS-рукопожатия, оно идет в потоке обработчика

    def _headers(self, code, ctype, length, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Robots-Tag", "noindex")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _html(self, code, body):
        data = body.encode("utf-8")
        self._headers(code, "text/html; charset=utf-8", len(data),
                      {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
        if self.command != "HEAD":
            self.wfile.write(data)

    def _fail(self, reason="не найдена", code=404):
        self._html(code, ERROR_PAGE.format(reason=html.escape(reason)))

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        # Connect может слать POST на /rest/*, тело не нужно
        length = min(int(self.headers.get("Content-Length") or 0), 65536)
        if length:
            self.rfile.read(length)
        self.do_GET()

    def client_ip(self):
        ip = self.client_address[0]
        headers = getattr(self, "headers", None)
        if not TRUSTED_PROXIES or headers is None:
            return ip
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ip
        if any(addr in net for net in TRUSTED_PROXIES):
            # X-Forwarded-For: последний адрес дописал сам прокси, левые части подделываются клиентом
            real = headers.get("X-Real-IP") or headers.get("X-Forwarded-For", "").split(",")[-1]
            if real.strip():
                return real.strip()[:64]
        return ip

    def _count(self, db, entry):
        entry["downloads"] += 1
        entry.setdefault("log", []).append(
            [int(time.time()), self.client_ip(), self.headers.get("User-Agent", "")[:200]])
        save_db(db)

    def _rest_error(self, code, kind, message, extra=None):
        # формат ошибок /rest/* у Access Server
        body = ('<?xml version="1.0" encoding="UTF-8"?>\n<Error>\n<Type>%s</Type>\n'
                '<Synopsis>REST method failed</Synopsis>\n<Message>%s</Message>\n</Error>\n'
                % (kind, html.escape(message))).encode()
        self._headers(code, "text/xml; charset=utf-8", len(body), extra)
        if self.command != "HEAD":
            self.wfile.write(body)

    def _basic_auth(self):
        header = self.headers.get("Authorization", "")
        if not header.lower().startswith("basic "):
            return None
        try:
            user, sep, code = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8").partition(":")
        except (ValueError, UnicodeDecodeError):
            return None
        return (user, code) if sep else None

    def _rest(self, parts):
        # /rest/<Method> или /p/<token>/rest/<Method>: ссылку вставляют в Connect целиком
        i = parts.index("rest")
        prefix, method = parts[:i], parts[i + 1:]
        token = prefix[1] if len(prefix) == 2 and prefix[0] == "p" else None
        if (prefix and token is None) or len(method) != 1 or method[0] not in REST_ENDPOINTS:
            return self._rest_error(404, "Not Found", "REST method not found")
        ip = self.client_ip()
        if too_many_fails(ip):
            return self._rest_error(429, "Too Many Requests", "too many failed attempts, try later",
                                    {"Retry-After": str(FAIL_WINDOW)})

        with _lock:
            db = load_db()
            if method[0] == "GetProfileViaToken":
                qtoken = (parse_qs(urlsplit(self.path).query).get("token") or [""])[0]
                entry = db.get(qtoken)
                entry = entry if entry and token_state(entry) is None else None
                attempted = bool(qtoken)
            else:
                creds = self._basic_auth()
                entry = find_by_credentials(db, *creds, token) if creds else None
                # запрос без Authorization - первый заход клиента за challenge, не перебор
                attempted = creds is not None
            path = resolve_profile(entry["file"]) if entry else None
            if path is None:
                if attempted:
                    _fails.setdefault(ip, []).append(time.time())
                return self._rest_error(401, "Authorization Required",
                                        "AUTH_FAILED: invalid or expired one-time password",
                                        {"WWW-Authenticate": 'Basic realm="OpenVPN Access Server"'})
            data = with_profile_name(path.read_bytes(), entry["file"])
            if self.command != "HEAD":
                self._count(db, entry)
        # как у Access Server (openvpn-rfc/webauth.md): REST отдает text/plain, токен-ссылка - профиль
        ctype = OVPN_MIME if method[0] == "GetProfileViaToken" else "text/plain; charset=utf-8"
        self._headers(200, ctype, len(data))
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_GET(self):
        # /p/<token> - страница с инструкцией, /d/<token>/<name>.ovpn - сам файл
        parts = unquote(self.path.split("?", 1)[0]).strip("/").split("/")
        if parts == ["healthz"]:
            self._headers(200, "text/plain", 2)
            if self.command == "GET":
                self.wfile.write(b"ok")
            return
        if "rest" in parts:
            return self._rest(parts)
        if self.command == "POST" or len(parts) < 2 or parts[0] not in ("p", "d"):
            return self._fail()
        kind, token = parts[0], parts[1]

        with _lock:
            db = load_db()
            entry = db.get(token)
            if entry is None:
                return self._fail()
            reason = token_state(entry)
            if reason:
                return self._fail(reason, 410)
            path = resolve_profile(entry["file"])
            if path is None:
                return self._fail("не найдена")

            if kind == "p":
                return self._page(token, entry)

            data = with_profile_name(path.read_bytes(), entry["file"])
            # HEAD и предзагрузка не тратят лимит
            if self.command == "GET":
                self._count(db, entry)

        fname = quote(entry["file"])
        self._headers(200, OVPN_MIME, len(data),
                      {"Content-Disposition": f"attachment; filename=\"{fname}\"; filename*=UTF-8''{fname}"})
        if self.command == "GET":
            self.wfile.write(data)

    def _page(self, token, entry):
        name = entry["file"]
        download = f"/d/{token}/{quote(name)}"
        left = (entry["max_downloads"] - entry["downloads"]) if entry["max_downloads"] else "без ограничений"
        expires = time.strftime("%d.%m.%Y %H:%M %Z", time.localtime(entry["expires"])) if entry["expires"] else "бессрочно"
        # формат токен-ссылок Access Server
        deeplink = f"openvpn://import-profile/{Handler.base_url}/rest/GetProfileViaToken?token={token}"
        app_import = ""
        if entry.get("code"):
            app_import = APP_IMPORT.format(url=html.escape(connect_url(Handler.base_url)),
                                           user=html.escape(entry["user"]), code=html.escape(entry["code"]))
        try:
            # эта же ссылка камерой на другое устройство
            qr = f'<div class="qr"><h3>Открыть на другом устройстве</h3>{qr_svg(f"{Handler.base_url}/p/{token}")}</div>'
        except ValueError:
            qr = ""
        # полный URL: за прокси с префиксом (/vpn/) путь от корня ушел бы мимо
        self._html(200, PAGE.format(
            name=html.escape(name), download=html.escape(Handler.base_url + download), deeplink=html.escape(deeplink),
            app_import=app_import, qr=qr, expires=expires, left=left))

    def log_message(self, fmt, *args):
        # токен в логе маскируем, healthcheck не шумит
        msg = fmt % args
        if "/healthz" in msg:
            return
        msg = re.sub(r"(/[pd]/|token=)([\w-]{6})[\w-]*", r"\1\2...", msg)
        sys.stderr.write(f"{self.log_date_time_string()} {self.client_ip()} {msg}\n")


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # обрывы и мусор вместо TLS - одной строкой, без трейсбека
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionError, TimeoutError)):
            sys.stderr.write(f"{client_address[0]} {type(exc).__name__}: {exc}\n")
        else:
            super().handle_error(request, client_address)


# ---------- CLI ----------

def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # пакет не отправляется, нужен только выбор интерфейса
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def default_base_url(args):
    if args.base_url:
        return args.base_url.rstrip("/")
    if DOMAIN:
        return f"https://{DOMAIN}"
    return f"{'https' if TLS_CERT else 'http'}://{lan_ip()}:{args.port}"


def cmd_add(args):
    names = [Path(f).name for f in args.files] if args.files else sorted(p.name for p in PROFILES_DIR.glob("*.ovpn"))
    if not names:
        sys.exit(f"Нет профилей в {PROFILES_DIR}")
    if args.user and len(names) != 1:
        sys.exit("--user указывается только для одного профиля")
    base = default_base_url(args)
    with _lock:
        db = load_db()
        for name in names:
            if resolve_profile(name) is None:
                sys.exit(f"Профиль не найден в {PROFILES_DIR}: {name}")
            token = secrets.token_urlsafe(24)
            user = args.user or Path(name).stem
            code = new_code()
            db[token] = {
                "file": name,
                "user": user,
                "code": code,
                "created": int(time.time()),
                "expires": int(time.time() + args.ttl * 3600) if args.ttl else 0,
                "max_downloads": args.max,
                "downloads": 0,
            }
            print(f"{name}\n  URL:     {connect_url(base)}\n  логин:   {user}\n  пароль:  {code}\n  страница: {base}/p/{token}")
            if args.qr:
                print_qr(f"{base}/p/{token}")
        save_db(db)


def cmd_list(args):
    db = load_db()
    base = default_base_url(args) if args.active else ""
    for token, e in db.items():
        state = token_state(e)
        if args.active and state:
            continue
        exp = time.strftime("%d.%m %H:%M", time.localtime(e["expires"])) if e["expires"] else "-"
        used = f"скачано {e['downloads']}/{e['max_downloads'] or 'inf'}  до {exp}"
        if args.active:
            # полные данные для повторной отправки пользователю
            print(f"{e['file']}  {used}\n  URL:     {connect_url(base)}\n  логин:   {e.get('user', '-')}\n"
                  f"  пароль:  {e.get('code', '-')}\n  страница: {base}/p/{token}")
        else:
            print(f"{token[:8]}  {e['file']:<30} {e.get('user', '-'):<16} {state or 'активна':<10} {used}")


def cmd_qr(args):
    base = default_base_url(args)
    hits = [(t, e) for t, e in load_db().items()
            if (t.startswith(args.target) or e["file"] == args.target) and token_state(e) is None]
    if not hits:
        sys.exit("Активных ссылок не найдено")
    for token, e in hits:
        print(f"{e['file']}  логин: {e.get('user', '-')}  пароль: {e.get('code', '-')}\n  страница: {base}/p/{token}")
        print_qr(f"{base}/p/{token}")


def cmd_revoke(args):
    with _lock:
        db = load_db()
        hits = [t for t, e in db.items() if t.startswith(args.target) or e["file"] == args.target]
        if not hits:
            sys.exit("Ничего не найдено")
        for t in hits:
            db[t]["revoked"] = True
            print(f"отозвана {t[:8]} ({db[t]['file']})")
        save_db(db)


def cmd_cleanup(args):
    with _lock:
        db = load_db()
        alive = {t: e for t, e in db.items() if token_state(e) is None}
        print(f"удалено записей: {len(db) - len(alive)}")
        save_db(alive)


def cmd_health(args):
    import urllib.request
    scheme = "https" if TLS_CERT else "http"
    ctx = ssl._create_unverified_context()  # localhost, а сертификат выписан на внешнее имя
    try:
        urllib.request.urlopen(f"{scheme}://127.0.0.1:{args.port}/healthz", timeout=2, context=ctx)
    except OSError as e:
        sys.exit(f"unhealthy: {e}")


def _raise_interrupt(*_):
    raise KeyboardInterrupt


def load_cert(ctx):
    # ssl не говорит, какого файла нет, поэтому проверяем сами
    for path in (TLS_CERT, TLS_KEY):
        if not os.path.exists(path):
            sys.exit(f"Нет файла {path}. Смонтируйте сертификаты в контейнер (-v /etc/letsencrypt:/etc/letsencrypt:ro)")
        if not os.access(path, os.R_OK):
            sys.exit(f"Нет прав на чтение {path} у uid {os.getuid()}. Для Let's Encrypt: "
                     "sudo setfacl -R -m u:10001:rX /etc/letsencrypt/live /etc/letsencrypt/archive")
    try:
        ctx.load_cert_chain(TLS_CERT, TLS_KEY)
    except ssl.SSLError as e:
        sys.exit(f"Не удалось загрузить сертификат {TLS_CERT} / {TLS_KEY}: {e}")


def watch_cert(ctx):
    """Certbot продлевает сертификат - подхватываем без перезапуска (новые соединения берут новый)."""
    def mtimes():
        return os.stat(TLS_CERT).st_mtime, os.stat(TLS_KEY).st_mtime  # stat идет по симлинкам live/

    last = mtimes()
    while True:
        time.sleep(CERT_CHECK_INTERVAL)
        try:
            cur = mtimes()
            if cur != last:
                ctx.load_cert_chain(TLS_CERT, TLS_KEY)
                last = cur
                print("сертификат перечитан", file=sys.stderr)
        except (OSError, ssl.SSLError) as e:
            print(f"не удалось перечитать сертификат: {e}", file=sys.stderr)


def cmd_serve(args):
    PROFILES_DIR.mkdir(exist_ok=True)
    Handler.base_url = default_base_url(args)
    httpd = Server((args.host, args.port), Handler)
    if TLS_CERT:
        if not TLS_KEY:
            sys.exit("OVPN_CERT задан без OVPN_KEY")
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        load_cert(ctx)
        # рукопожатие в потоке обработчика, иначе один молчащий клиент блокирует accept()
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
        threading.Thread(target=watch_cert, args=(ctx,), daemon=True).start()
    mode = f"HTTPS ({TLS_CERT})" if TLS_CERT else "HTTP"
    print(f"Слушаю {args.host}:{args.port}, {mode}, адрес для Connect {connect_url(Handler.base_url)}",
          file=sys.stderr)
    # PID 1 в контейнере не получает SIGTERM по умолчанию
    signal.signal(signal.SIGTERM, _raise_interrupt)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def main():
    p = argparse.ArgumentParser(description="Раздача .ovpn профилей по одноразовым ссылкам")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--port", type=int, default=int(os.environ.get("OVPN_PORT", 8080)))
    common.add_argument("--base-url", default=os.environ.get("OVPN_BASE_URL"),
                        help="внешний адрес, если сервер за NAT/прокси/в докере (https://vpn.example.com)")

    s = sub.add_parser("serve", parents=[common], help="запустить сервер")
    s.add_argument("--host", default="0.0.0.0")
    s.set_defaults(func=cmd_serve)

    a = sub.add_parser("add", parents=[common], help="выдать ссылки (без аргументов - на все профили)")
    a.add_argument("files", nargs="*", help="имена файлов в profiles/")
    a.add_argument("--ttl", type=float, default=24, help="срок жизни, часов (0 - бессрочно)")
    a.add_argument("--max", type=int, default=3, help="лимит скачиваний (0 - без лимита)")
    a.add_argument("--user", help="логин для импорта из приложения (по умолчанию имя файла)")
    a.add_argument("--no-qr", dest="qr", action="store_false", help="не печатать QR со ссылкой на страницу")
    a.set_defaults(func=cmd_add)

    q = sub.add_parser("qr", parents=[common], help="QR живой ссылки по префиксу токена или имени файла")
    q.add_argument("target")
    q.set_defaults(func=cmd_qr)

    sub.add_parser("health", parents=[common], help="проверка для HEALTHCHECK").set_defaults(func=cmd_health)
    ls = sub.add_parser("list", parents=[common], help="список ссылок")
    ls.add_argument("-a", "--active", action="store_true", help="только живые, с полной ссылкой и паролем")
    ls.set_defaults(func=cmd_list)
    r = sub.add_parser("revoke", help="отозвать по префиксу токена или имени файла")
    r.add_argument("target")
    r.set_defaults(func=cmd_revoke)
    sub.add_parser("cleanup", help="удалить истекшие/отозванные записи").set_defaults(func=cmd_cleanup)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
