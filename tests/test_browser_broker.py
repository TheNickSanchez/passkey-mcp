"""Tests for Wave 3 deterministic CDP browser credential broker using a local mock WS server."""

import base64
import contextlib
import hashlib
import json
import socket
import struct
import threading
from unittest.mock import patch

import pytest

import passkey.browser_broker as broker_mod
from passkey.browser_broker import _WS_GUID, cdp_autofill, verify_exact_origin_match
from passkey.keychain import PasskeyError, save_entry
from passkey.mcp_server import passkey_cdp_autofill
from passkey.models import Entry
from passkey.settings import set_setting


class _MockCDPServer:
    """Minimal loopback HTTP (/json) + RFC-6455 WebSocket server for hermetic CDP tests.

    Attempts real AF_INET 127.0.0.1 loopback first; if the test runner's OS sandbox
    blocks AF_INET connect() with EPERM, transparently routes _connect_socket over
    real OS AF_UNIX socketpair() streams so HTTP /json + RFC-6455 framing are tested
    end-to-end without network privileges.
    """

    def __init__(self, page_origin: str, *, has_password_input: bool = True) -> None:
        self.page_origin = page_origin
        self.has_password_input = has_password_input
        self.received_calls: list[dict] = []
        self._stop = threading.Event()
        self._tcp_sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._patcher = None
        self.port = 9222

    def _can_use_tcp_loopback(self) -> bool:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port = srv.getsockname()[1]
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                pass
            return True
        except OSError:
            return False
        finally:
            srv.close()

    def start(self) -> "_MockCDPServer":
        if self._can_use_tcp_loopback():
            self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._tcp_sock.bind(("127.0.0.1", 0))
            self._tcp_sock.listen(5)
            self.port = self._tcp_sock.getsockname()[1]
            self._thread = threading.Thread(target=self._serve_tcp, daemon=True)
            self._thread.start()
        else:
            self.port = 49222
            orig_connect = broker_mod._connect_socket

            def _pair_connect(host: str, port: int, timeout: float = 5.0) -> socket.socket:
                if host not in broker_mod._LOOPBACK_HOSTS:
                    return orig_connect(host, port, timeout)
                if port != self.port:
                    raise ConnectionRefusedError(f"No mock CDP server on port {port}")
                client_sock, server_sock = socket.socketpair()
                client_sock.settimeout(timeout)
                threading.Thread(
                    target=self._handle_conn, args=(server_sock,), daemon=True
                ).start()
                return client_sock

            self._patcher = patch.object(broker_mod, "_connect_socket", side_effect=_pair_connect)
            self._patcher.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._patcher is not None:
            self._patcher.stop()
            self._patcher = None
        if self._tcp_sock is not None:
            with contextlib.suppress(OSError):
                self._tcp_sock.close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def __enter__(self) -> "_MockCDPServer":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def _serve_tcp(self) -> None:
        assert self._tcp_sock is not None
        self._tcp_sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self._tcp_sock.accept()
            except OSError:
                continue
            threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()

    def _handle_conn(self, conn: socket.socket) -> None:
        conn.settimeout(3.0)
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            head_raw, leftover = data.split(b"\r\n\r\n", 1)
            lines = head_raw.decode("latin-1").split("\r\n")
            req_line = lines[0]
            headers = {}
            for ln in lines[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            if req_line.startswith("GET /json "):
                body = json.dumps(
                    [
                        {
                            "type": "page",
                            "webSocketDebuggerUrl": f"ws://127.0.0.1:{self.port}/devtools/page/tab1",
                        }
                    ]
                ).encode("utf-8")
                resp = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii") + body
                conn.sendall(resp)
                return

            ws_key = headers.get("sec-websocket-key", "")
            accept = base64.b64encode(
                hashlib.sha1((ws_key + _WS_GUID).encode("ascii")).digest()
            ).decode("ascii")
            upgrade = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
            ).encode("ascii")
            conn.sendall(upgrade)

            rx = bytearray(leftover)
            while not self._stop.is_set():
                msg = self._read_client_frame(conn, rx)
                if msg is None:
                    break
                req = json.loads(msg)
                self.received_calls.append(req)
                call_id = req["id"]
                method = req["method"]
                params = req.get("params", {})

                if method == "Runtime.evaluate":
                    expr = params.get("expression", "")
                    if "window.location.origin" in expr:
                        val = self.page_origin
                    elif "password" in expr:
                        val = self.has_password_input
                    else:
                        val = True
                    result = {"result": {"type": "any", "value": val}}
                elif method == "Network.setCookie":
                    result = {"success": True}
                else:
                    result = {}

                reply_bytes = json.dumps({"id": call_id, "result": result}).encode("utf-8")
                self._send_server_frame(conn, reply_bytes)
        except Exception:
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    @staticmethod
    def _read_client_frame(conn: socket.socket, rx: bytearray) -> str | None:
        def _need(n: int) -> bytes | None:
            while len(rx) < n:
                chunk = conn.recv(4096)
                if not chunk:
                    return None
                rx.extend(chunk)
            out = bytes(rx[:n])
            del rx[:n]
            return out

        hdr = _need(2)
        if hdr is None:
            return None
        opcode = hdr[0] & 0x0F
        if opcode == 0x8:
            return None
        masked = bool(hdr[1] & 0x80)
        length = hdr[1] & 0x7F
        if length == 126:
            ext = _need(2)
            if ext is None:
                return None
            length = struct.unpack("!H", ext)[0]
        elif length == 127:
            ext = _need(8)
            if ext is None:
                return None
            length = struct.unpack("!Q", ext)[0]
        mask_key = _need(4) if masked else b""
        if mask_key is None:
            return None
        payload = _need(length)
        if payload is None:
            return None
        if masked:
            payload = bytes(b ^ mask_key[i & 3] for i, b in enumerate(payload))
        return payload.decode("utf-8")

    @staticmethod
    def _send_server_frame(conn: socket.socket, payload: bytes) -> None:
        header = bytearray([0x81])
        n = len(payload)
        if n < 126:
            header.append(n)
        else:
            header.append(126)
            header.extend(struct.pack("!H", n))
        conn.sendall(bytes(header) + payload)


class TestCDPBrowserBroker:
    """Tests for CDP origin verification, credential injection, and MCP opt-in gate."""

    def test_origin_matching_strictness(self):
        verify_exact_origin_match("https://app.example.com", "https://app.example.com:443")
        with pytest.raises(PasskeyError, match="mismatch"):
            verify_exact_origin_match("https://app.example.com", "https://evil.example.com")
        with pytest.raises(PasskeyError, match="mismatch"):
            verify_exact_origin_match("https://app.example.com", "https://app.example.com:8443")
        with pytest.raises(PasskeyError):
            verify_exact_origin_match("https://app.example.com", "http://app.example.com")

    def test_autofills_username_password_and_cookie_without_returning_secrets(self):
        save_entry(
            Entry(
                name="portal_login",
                fields={
                    "USERNAME": "alice@example.com",
                    "PASSWORD": "s3cr3t_browser_password!",
                    "SESSION_COOKIE": "sess_tok_abcdef12345",
                },
                config={"ORIGIN": "https://portal.example.com"},
            )
        )
        with _MockCDPServer("https://portal.example.com") as srv:
            res = cdp_autofill("portal_login", f"ws://127.0.0.1:{srv.port}")

        assert res == {
            "filled": True,
            "origin": "https://portal.example.com",
            "fields_injected": ["USERNAME", "PASSWORD", "SESSION_COOKIE"],
        }
        assert "s3cr3t_browser_password!" not in json.dumps(res)
        assert "sess_tok_abcdef12345" not in json.dumps(res)

        inserted_texts = [
            c["params"]["text"]
            for c in srv.received_calls
            if c["method"] == "Input.insertText"
        ]
        assert inserted_texts == ["alice@example.com", "s3cr3t_browser_password!"]

    def test_aborts_before_touching_secrets_on_phishing_origin_mismatch(self):
        save_entry(
            Entry(
                name="bank",
                fields={"PASSWORD": "never_send_to_phish_site"},
                config={"ORIGIN": "https://login.bank.example"},
                policy="prompt",
            )
        )
        with (
            _MockCDPServer("https://login-bank.phishing.example") as srv,
            patch("passkey.auth.authenticate") as mock_auth,
            pytest.raises(PasskeyError, match="origin mismatch"),
        ):
            cdp_autofill("bank", f"ws://127.0.0.1:{srv.port}/devtools/page/1")
            # Must fail BEFORE prompting auth or sending Input.insertText
        mock_auth.assert_not_called()
        assert not any(c["method"] == "Input.insertText" for c in srv.received_calls)

    def test_rejects_non_loopback_cdp_url_and_gates_mcp_tool(self):
        save_entry(
            Entry(
                name="corp",
                fields={"PASSWORD": "corp_pw_1234"},
                config={"ORIGIN": "https://corp.example.com"},
            )
        )
        with pytest.raises(PasskeyError, match="loopback"):
            cdp_autofill("corp", "ws://192.168.1.50:9222/devtools/page/1")

        # MCP tool disabled by default
        disabled_res = passkey_cdp_autofill("corp", "ws://127.0.0.1:9222")
        assert disabled_res["filled"] is False
        assert "disabled" in disabled_res["message"].lower()

        # Enable setting and run via MCP tool against loopback mock server
        set_setting("mcp_browser_broker", True)
        with _MockCDPServer("https://corp.example.com") as srv:
            mcp_res = passkey_cdp_autofill("corp", f"ws://127.0.0.1:{srv.port}")
        assert mcp_res["filled"] is True
        assert "corp_pw_1234" not in json.dumps(mcp_res)
