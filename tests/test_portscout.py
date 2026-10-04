"""Tests for port_scout.py. Loopback only — no external network."""

import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from port_scout import grab_banner, parse_ports, resolve_target


def test_parse_single_port():
    assert parse_ports("80") == [80]


def test_parse_range():
    assert parse_ports("20-22") == [20, 21, 22]


def test_parse_list():
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_parse_rejects_bad_port():
    try:
        parse_ports("99999")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_parse_rejects_inverted_range():
    try:
        parse_ports("100-10")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_resolve_localhost():
    assert resolve_target("localhost") == "127.0.0.1"


def _open_test_server():
    """Bind a listening socket on an ephemeral port; return (sock, port)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def accept_once():
        try:
            conn, _ = srv.accept()
            conn.sendall(b"TEST-BANNER 1.0\r\n")
            conn.close()
        except OSError:
            pass

    threading.Thread(target=accept_once, daemon=True).start()
    return srv, port


def _closed_port():
    """Grab an ephemeral port and release it — almost certainly closed after."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_open_port_detected_with_banner():
    srv, port = _open_test_server()
    try:
        is_open, banner = grab_banner("127.0.0.1", port, timeout=2.0)
        assert is_open is True
        assert "TEST-BANNER" in banner
    finally:
        srv.close()


def test_closed_port_reported_closed():
    port = _closed_port()
    is_open, banner = grab_banner("127.0.0.1", port, timeout=1.0)
    assert is_open is False
    assert banner == ""
