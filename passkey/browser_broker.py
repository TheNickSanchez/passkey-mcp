"""Deterministic Chrome DevTools Protocol (CDP) credential broker outside the LLM loop."""

import base64
import contextlib
import hashlib
import json
import os
import socket
import struct
from collections.abc import Callable
from urllib.parse import urlparse

from .audit import log_operation
from .keychain import PasskeyError, get_entry
from .leases import authorize_entry_access
from .models import Entry

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

_FOCUS_USERNAME_JS = """
(() => {
  const selectors = [
    'input[autocomplete="username"]',
    'input[type="email"]',
    'input[name*="user" i]',
    'input[name*="email" i]',
    'input[name*="login" i]',
    'input[type="text"]'
  ];
  for (const sel of selectors) {
    const el = document.querySelector(sel);
    if (el && !el.disabled && !el.readOnly) {
      el.focus();
      el.value = '';
      el.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    }
  }
  return false;
})()
"""

_FOCUS_PASSWORD_JS = """
(() => {
  const el = document.querySelector('input[type="password"]');
  if (el && !el.disabled && !el.readOnly) {
    el.focus();
    el.value = '';
    el.dispatchEvent(new Event('input', { bubbles: true }));
    return true;
  }
  return false;
})()
"""


def normalize_origin(origin_url: str) -> tuple[str, str, int]:
    """Parse and normalize an origin into (scheme, hostname, effective_port)."""
    if not origin_url or not isinstance(origin_url, str):
        raise PasskeyError("Origin URL cannot be empty")
    parsed = urlparse(origin_url.strip())
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    if scheme not in ("https", "http") or not host:
        raise PasskeyError(f"Invalid origin URL '{origin_url}' (expected http(s)://host[:port])")
    if scheme == "http" and host not in _LOOPBACK_HOSTS:
        raise PasskeyError(
            f"Refusing insecure non-HTTPS origin '{origin_url}' (HTTP is only permitted on localhost)"
        )
    try:
        port = parsed.port
    except ValueError as e:
        raise PasskeyError(f"Invalid port in origin '{origin_url}'") from e
    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, host, port


def verify_exact_origin_match(expected_origin: str, actual_origin: str) -> None:
    """Require exact (scheme, hostname, effective_port) match before touching credentials."""
    exp_tuple = normalize_origin(expected_origin)
    try:
        act_tuple = normalize_origin(actual_origin)
    except PasskeyError as e:
        raise PasskeyError(
            f"CDP origin verification failed: active page origin '{actual_origin}' is invalid "
            f"(expected '{expected_origin}'): {e}"
        ) from e

    if exp_tuple != act_tuple:
        raise PasskeyError(
            f"CDP origin mismatch: expected '{expected_origin}', but active browser tab is at '{actual_origin}'"
        )


def _connect_socket(host: str, port: int, timeout: float = 5.0) -> socket.socket:
    """Open a direct loopback TCP socket without consulting HTTP_PROXY env vars."""
    if host not in _LOOPBACK_HOSTS:
        raise PasskeyError(f"Refusing non-loopback CDP socket connection to '{host}'")
    return socket.create_connection((host, port), timeout=timeout)


def _fetch_loopback_json(host: str, port: int, path: str, timeout: float = 3.0) -> object:
    """Perform a minimal direct HTTP/1.1 GET on loopback (immune to HTTP_PROXY)."""
    sock = _connect_socket(host, port, timeout=timeout)
    try:
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Accept: application/json\r\n"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(req.encode("ascii"))
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > 1_048_576:
                raise PasskeyError("CDP /json response exceeded 1 MiB limit")
        raw = b"".join(chunks)
        if b"\r\n\r\n" not in raw:
            raise PasskeyError("Malformed HTTP response from CDP /json endpoint")
        header_bytes, body_bytes = raw.split(b"\r\n\r\n", 1)
        status_line = header_bytes.decode("latin-1").split("\r\n", 1)[0]
        if " 200" not in status_line:
            raise PasskeyError(f"CDP /json returned unexpected status: {status_line}")
        return json.loads(body_bytes.decode("utf-8"))
    finally:
        with contextlib.suppress(OSError):
            sock.close()


def _resolve_loopback_ws_url(cdp_url: str) -> tuple[str, int, str]:
    """Validate that cdp_url targets loopback and resolve /json page target if needed."""
    parsed = urlparse(cdp_url.strip())
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    if scheme not in ("ws", "http") or host not in _LOOPBACK_HOSTS:
        raise PasskeyError(
            f"CDP broker only connects to loopback ws://127.0.0.1 or ws://localhost endpoints; got '{cdp_url}'"
        )
    port = parsed.port
    if not port:
        raise PasskeyError(f"CDP URL must specify an explicit port (e.g. ws://127.0.0.1:9222): '{cdp_url}'")

    path = parsed.path or ""
    if parsed.query:
        path = f"{path}?{parsed.query}"

    # If user gave root port URL (ws://127.0.0.1:9222), discover active page target via /json
    if not path or path == "/":
        list_url = f"http://{host}:{port}/json"
        try:
            targets = _fetch_loopback_json(host, port, "/json", timeout=3.0)
        except PasskeyError:
            raise
        except Exception as e:
            raise PasskeyError(f"Failed to query CDP target list at '{list_url}': {e}") from e

        ws_target = None
        if isinstance(targets, list):
            for t in targets:
                if isinstance(t, dict) and t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                    ws_target = str(t["webSocketDebuggerUrl"])
                    break
            if ws_target is None:
                for t in targets:
                    if isinstance(t, dict) and t.get("webSocketDebuggerUrl"):
                        ws_target = str(t["webSocketDebuggerUrl"])
                        break
        if not ws_target:
            raise PasskeyError(f"No debuggable page target found at '{list_url}'")
        return _resolve_loopback_ws_url(ws_target)

    return host, port, path


class _CDPWebSocketClient:
    """Minimal stdlib RFC-6455 WebSocket client for local Chrome DevTools JSON-RPC."""

    def __init__(self, host: str, port: int, path: str, timeout: float = 5.0) -> None:
        self._host = host
        self._port = port
        self._path = path
        self._sock = _connect_socket(host, port, timeout=timeout)
        self._next_id = 1
        self._handshake()

    def _handshake(self) -> None:
        raw_key = os.urandom(16)
        ws_key = base64.b64encode(raw_key).decode("ascii")
        req = (
            f"GET {self._path} HTTP/1.1\r\n"
            f"Host: {self._host}:{self._port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self._sock.sendall(req.encode("ascii"))

        buf = bytearray()
        while b"\r\n\r\n" not in buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise PasskeyError("CDP WebSocket handshake failed: connection closed early")
            buf.extend(chunk)
            if len(buf) > 65536:
                raise PasskeyError("CDP WebSocket handshake header exceeded limit")

        header_bytes, leftover = bytes(buf).split(b"\r\n\r\n", 1)
        self._rx_buf = bytearray(leftover)
        header_lines = header_bytes.decode("latin-1").split("\r\n")
        if not header_lines or "101" not in header_lines[0]:
            raise PasskeyError(f"CDP WebSocket upgrade rejected: {header_lines[0] if header_lines else 'empty'}")

        headers: dict[str, str] = {}
        for line in header_lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        expected_accept = base64.b64encode(
            hashlib.sha1((ws_key + _WS_GUID).encode("ascii")).digest()
        ).decode("ascii")
        if headers.get("sec-websocket-accept") != expected_accept:
            raise PasskeyError("CDP WebSocket handshake failed: invalid Sec-WebSocket-Accept")

    def _read_exact(self, n: int) -> bytes:
        while len(self._rx_buf) < n:
            chunk = self._sock.recv(max(4096, n - len(self._rx_buf)))
            if not chunk:
                raise PasskeyError("Unexpected EOF reading CDP WebSocket frame")
            self._rx_buf.extend(chunk)
        out = bytes(self._rx_buf[:n])
        del self._rx_buf[:n]
        return out

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        mask_key = os.urandom(4)
        header = bytearray([0x80 | (opcode & 0x0F)])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        header.extend(mask_key)
        masked = bytes(b ^ mask_key[i & 3] for i, b in enumerate(payload))
        self._sock.sendall(bytes(header) + masked)

    def _recv_message(self) -> str:
        fragments: list[bytes] = []
        while True:
            b0, b1 = self._read_exact(2)
            fin = bool(b0 & 0x80)
            opcode = b0 & 0x0F
            masked = bool(b1 & 0x80)
            length = b1 & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read_exact(8))[0]
            mask_key = self._read_exact(4) if masked else b""
            data = self._read_exact(length)
            if masked:
                data = bytes(b ^ mask_key[i & 3] for i, b in enumerate(data))

            if opcode == 0x8:  # Close
                raise PasskeyError("CDP WebSocket closed by browser")
            if opcode == 0x9:  # Ping -> Pong
                self._send_frame(0xA, data)
                continue
            if opcode == 0xA:  # Pong
                continue

            fragments.append(data)
            if fin:
                return b"".join(fragments).decode("utf-8")

    def call(self, method: str, params: dict | None = None) -> dict:
        call_id = self._next_id
        self._next_id += 1
        msg = {"id": call_id, "method": method, "params": params or {}}
        self._send_frame(0x1, json.dumps(msg).encode("utf-8"))

        while True:
            raw = self._recv_message()
            resp = json.loads(raw)
            if resp.get("id") != call_id:
                continue  # Ignore async CDP event notifications
            if "error" in resp:
                err_msg = resp["error"].get("message", str(resp["error"]))
                raise PasskeyError(f"CDP command '{method}' failed: {err_msg}")
            return resp.get("result", {})

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self._send_frame(0x8, b"")
        with contextlib.suppress(OSError):
            self._sock.close()


def cdp_autofill(
    entry_name: str,
    cdp_url: str,
    *,
    authorize_fn: Callable[[Entry], None] | None = None,
) -> dict:
    """Verify exact browser tab origin over CDP and inject credentials outside LLM context."""
    entry = get_entry(entry_name)
    if entry is None:
        raise PasskeyError(f"Entry '{entry_name}' not found")

    expected_origin = entry.config.get("ORIGIN") or entry.fields.get("ORIGIN")
    if not expected_origin:
        raise PasskeyError(
            f"Entry '{entry_name}' has no ORIGIN configured in config (e.g. https://login.example.com)."
        )

    # Validate expected_origin format before opening any socket
    exp_scheme, exp_host, _ = normalize_origin(expected_origin)
    ws_host, ws_port, ws_path = _resolve_loopback_ws_url(cdp_url)

    client = _CDPWebSocketClient(ws_host, ws_port, ws_path)
    try:
        eval_res = client.call(
            "Runtime.evaluate",
            {"expression": "window.location.origin", "returnByValue": True},
        )
        actual_origin = str(eval_res.get("result", {}).get("value", "") or "")
        try:
            verify_exact_origin_match(expected_origin, actual_origin)
        except PasskeyError:
            log_operation(
                "browser_fill",
                entry.name,
                details={"origin": actual_origin},
                success=False,
            )
            raise

        auth_cb = authorize_fn or (
            lambda ent: authorize_entry_access(ent, operation=f"browser autofill for {actual_origin}")
        )
        auth_cb(entry)

        fields_injected: list[str] = []

        # 1. Optional USERNAME / EMAIL
        for user_key in ("USERNAME", "EMAIL"):
            user_val = entry.fields.get(user_key) or entry.config.get(user_key)
            if user_val:
                focus_res = client.call(
                    "Runtime.evaluate",
                    {"expression": _FOCUS_USERNAME_JS, "returnByValue": True},
                )
                if focus_res.get("result", {}).get("value") is True:
                    client.call("Input.insertText", {"text": user_val})
                    fields_injected.append(user_key)
                break

        # 2. Optional PASSWORD
        password_val = entry.fields.get("PASSWORD")
        if password_val:
            focus_pw = client.call(
                "Runtime.evaluate",
                {"expression": _FOCUS_PASSWORD_JS, "returnByValue": True},
            )
            if focus_pw.get("result", {}).get("value") is not True:
                raise PasskeyError(
                    f"No active password input field found on '{actual_origin}'"
                )
            client.call("Input.insertText", {"text": password_val})
            fields_injected.append("PASSWORD")

        # 3. Optional SESSION_COOKIE
        cookie_val = entry.fields.get("SESSION_COOKIE")
        if cookie_val:
            cookie_name = entry.config.get("COOKIE_NAME", "session")
            client.call("Network.enable", {})
            cookie_res = client.call(
                "Network.setCookie",
                {
                    "name": cookie_name,
                    "value": cookie_val,
                    "domain": exp_host,
                    "path": "/",
                    "secure": exp_scheme == "https",
                    "httpOnly": True,
                },
            )
            if cookie_res.get("success", True) is False:
                raise PasskeyError(f"Browser rejected Network.setCookie for '{exp_host}'")
            fields_injected.append("SESSION_COOKIE")

        if not fields_injected:
            raise PasskeyError(
                f"Entry '{entry.name}' has no injectable browser fields (USERNAME, EMAIL, PASSWORD, SESSION_COOKIE)."
            )

        log_operation(
            "browser_fill",
            entry.name,
            details={"origin": actual_origin, "fields_injected": fields_injected},
            success=True,
        )
        return {
            "filled": True,
            "origin": actual_origin,
            "fields_injected": fields_injected,
        }
    finally:
        client.close()
