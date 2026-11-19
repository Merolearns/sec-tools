"""sec-tools web UI: passcheck and port-scout behind a small dashboard.

Thin layer over passcheck.py / port_scout.py — the CLIs are untouched.
Every number on these pages comes from the same functions the command
line uses. Passwords are checked in memory only: never logged, never
stored, never sent back to the browser.
"""

import socket
import time

from flask import Flask, render_template, request

from passcheck import crack_estimates, load_common_passwords, score_password
from port_scout import COMMON_PORTS, SERVICE_NAMES, parse_ports, scan

app = Flask(__name__)

COMMON = load_common_passwords()

# the web form caps a single scan so a stray "1-65535" doesn't tie the
# page up for minutes; the CLI has no such cap
MAX_WEB_PORTS = 1024


def _resolve(target):
    """Hostname/IP -> (ip, None), or (None, plain-English error).

    port_scout.resolve_target() exits the process on failure, so the
    web app does its own lookup instead of calling it.
    """
    try:
        return socket.gethostbyname(target), None
    except socket.gaierror:
        return None, (f"Can't resolve {target!r} — check the hostname or "
                      "IP address and try again.")


def _score_class(label):
    return {"weak": "score-weak", "fair": "score-fair",
            "good": "score-good", "strong": "score-strong"}.get(label, "")


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/passcheck", methods=["GET", "POST"])
def passcheck_page():
    result = estimates = error = None
    if request.method == "POST":
        # the password lives in this local variable only; it is never
        # logged and never passed back to the template
        password = request.form.get("password") or ""
        if not password:
            error = "Enter a password first."
        else:
            result = score_password(password, COMMON)
            estimates = crack_estimates(password)
    return render_template(
        "passcheck.html",
        result=result,
        estimates=estimates,
        error=error,
        score_class=_score_class(result["label"]) if result else "",
    )


@app.route("/port-scout", methods=["GET", "POST"])
def port_scout_page():
    rows = error = summary = None
    # form defaults, echoed back so a re-render keeps what was typed
    target = "localhost"
    ports_spec = ""
    use_common = True
    threads = 100
    timeout = 1.0
    if request.method == "POST":
        target = (request.form.get("target") or "").strip()
        ports_spec = (request.form.get("ports") or "").strip()
        use_common = request.form.get("common") == "on"
        try:
            threads = int(request.form.get("threads") or 100)
        except ValueError:
            error = "Threads must be a whole number."
        try:
            timeout = float(request.form.get("timeout") or 1.0)
        except ValueError:
            error = error or "Timeout must be a number of seconds."
        if not error:
            if not target:
                error = "Enter a hostname or IP address to scan."
            elif not 1 <= threads <= 1000:
                error = "Threads must be between 1 and 1000."
            elif not 0 < timeout <= 30:
                error = "Timeout must be between 0 and 30 seconds."
        if not error:
            if use_common and ports_spec:
                # both were submitted (e.g. a no-JS form): say so instead
                # of silently dropping the typed list for the preset
                error = ("You gave a port list and the common-ports preset. "
                         "Untick the preset to scan your own list, or clear "
                         "the list to scan the preset.")
            else:
                try:
                    ports = COMMON_PORTS if use_common else parse_ports(ports_spec)
                except ValueError as exc:
                    error = str(exc)
                else:
                    if len(ports) > MAX_WEB_PORTS:
                        error = (f"That's {len(ports)} ports — the web UI caps "
                                 f"a scan at {MAX_WEB_PORTS}. Narrow the range "
                                 "or use the CLI for a full sweep.")
        if not error:
            ip, resolve_error = _resolve(target)
            if resolve_error:
                error = resolve_error
            else:
                start = time.time()
                results = scan(ip, ports, threads, timeout)
                elapsed = time.time() - start
                rows = [{
                    "port": port,
                    "state": "open" if is_open else "closed",
                    "service": SERVICE_NAMES.get(port, "-"),
                    "banner": banner,
                } for port, (is_open, banner) in sorted(results.items())]
                open_count = sum(1 for r in rows if r["state"] == "open")
                summary = {
                    "target": target,
                    "ip": ip,
                    "scanned": len(ports),
                    "open": open_count,
                    "elapsed": f"{elapsed:.2f}",
                }
    return render_template(
        "port_scout.html",
        rows=rows,
        error=error,
        summary=summary,
        target=target,
        ports_spec=ports_spec,
        use_common=use_common,
        threads=threads,
        timeout=timeout,
    )


@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(debug=True)
