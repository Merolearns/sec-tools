"""Smoke tests for the sec-tools web UI. Loopback only — no external
network. Passwords here are throwaway test strings, never real ones."""

import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_home_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"passcheck" in resp.data
    assert b"port-scout" in resp.data
    # authorized-testing warning is on the home page too
    assert b"authorized testing only" in resp.data


def test_passcheck_form_loads(client):
    resp = client.get("/passcheck")
    assert resp.status_code == 200
    assert b"Password to check" in resp.data


def test_passcheck_weak_password(client):
    resp = client.post("/passcheck", data={"password": "password"})
    assert resp.status_code == 200
    assert b"commonly used" in resp.data
    assert b"weak" in resp.data
    # the password itself is never echoed back in the page
    assert b'value="password"' not in resp.data


def test_passcheck_strong_password(client):
    resp = client.post("/passcheck", data={"password": "xQ9#mZ2!vLp4@wT"})
    assert resp.status_code == 200
    assert b"strong" in resp.data


def test_passcheck_empty_password(client):
    resp = client.post("/passcheck", data={"password": ""})
    assert resp.status_code == 200
    assert b"Enter a password first" in resp.data


def test_passcheck_very_long_password(client):
    # a 200-char mixed password used to 500 the page: crack_estimates
    # raised OverflowError on a keyspace too big for a float
    resp = client.post("/passcheck", data={"password": "Aa1!" * 50})
    assert resp.status_code == 200
    assert b"centuries" in resp.data


def test_port_scout_form_loads(client):
    resp = client.get("/port-scout")
    assert resp.status_code == 200
    assert b"Target host" in resp.data
    assert b"authorized testing only" in resp.data


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


def test_port_scout_finds_open_loopback_port(client):
    srv, port = _open_test_server()
    try:
        resp = client.post("/port-scout", data={
            "target": "127.0.0.1",
            "ports": str(port),
            "threads": "10",
            "timeout": "1.0",
        })
        assert resp.status_code == 200
        assert str(port).encode() in resp.data
        assert b"open" in resp.data
        assert b"TEST-BANNER" in resp.data
        assert b"1 open" in resp.data or b">1<" in resp.data
    finally:
        srv.close()


def test_port_scout_bad_target_is_a_plain_error(client):
    # an invalid numeric IP fails resolution without touching the network
    # (a made-up hostname can be answered by a sandbox DNS shim instead)
    resp = client.post("/port-scout", data={
        "target": "999.999.999.999",
        "ports": "80",
        "threads": "10",
        "timeout": "1.0",
    })
    assert resp.status_code == 200
    assert b"Can&#39;t resolve" in resp.data or b"resolve" in resp.data
    assert b"Traceback" not in resp.data


def test_port_scout_bad_ports_is_a_plain_error(client):
    resp = client.post("/port-scout", data={
        "target": "localhost",
        "ports": "abc",
        "threads": "10",
        "timeout": "1.0",
    })
    assert resp.status_code == 200
    assert b"bad port" in resp.data
    assert b"Traceback" not in resp.data


def test_port_scout_preset_and_list_is_a_plain_error(client):
    # a typed list plus the preset used to silently drop the list and
    # scan the preset (a no-JS form can submit both at once)
    resp = client.post("/port-scout", data={
        "target": "localhost",
        "ports": "8080",
        "common": "on",
        "threads": "10",
        "timeout": "1.0",
    })
    assert resp.status_code == 200
    assert b"common-ports preset" in resp.data
    assert b"Traceback" not in resp.data


def test_unknown_route_is_404(client):
    resp = client.get("/no-such-page")
    assert resp.status_code == 404
    assert b"Page not found" in resp.data
