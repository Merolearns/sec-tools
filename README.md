# sec-tools

Two small defensive security CLI tools I wrote while studying for my cybersecurity concentration. Both are 100% local — no network calls except the ones port-scout explicitly makes to the target you give it.

**For learning and authorized testing only.** Don't scan anything you don't own or have permission to test.

## Web UI

Both tools also run in the browser — same code underneath, results as
designed pages instead of terminal output.

```bash
pip install -r requirements.txt
python3 app.py
```

Then open http://127.0.0.1:5000/ — the home page links to both tools:

- **passcheck** (`/passcheck`): type a password and get its score out of
  100, entropy, rough brute-force times, and the same issues and
  suggestions the CLI prints. The password is checked in memory and never
  stored, logged, or shown back on the page. Entering `password` scores
  10/100 (weak) and flags it as one of the most commonly used passwords.
- **port-scout** (`/port-scout`): enter a host and a port list (or the
  common-ports preset) and get a table of each port's state, best-guess
  service, and banner, plus an open-port count and elapsed time. The web
  form caps a scan at 1024 ports so a stray `1-65535` doesn't tie the page
  up; the CLI has no cap.

The CLIs are unchanged — `python3 passcheck.py` and
`python3 port_scout.py <target> --common` still work exactly as before.

## Tools

### port-scout

Multithreaded TCP connect port scanner with banner grabbing.

```bash
python3 port_scout.py scanme.nmap.org --common
python3 port_scout.py 192.168.1.1 --ports 20-100 --threads 50 --timeout 0.5
```

It resolves the target, scans with a thread pool, tries to read a service banner from each open port, and prints a summary with elapsed time. Service names are best guesses from a small built-in table of well-known ports. `scanme.nmap.org` exists specifically for practicing this kind of thing.

Example output:

```
scanning 127.0.0.1 (127.0.0.1) — 29 ports, 100 threads

PORT    STATE    SERVICE     BANNER
21      closed   ftp
22      open     ssh         SSH-2.0-OpenSSH_8.9
80      closed   http
...

done: 29 ports in 1.84s — 1 open
```

### passcheck

Password strength analyzer. Reads the password with `getpass` (no echo), checks it against a list of ~900 commonly-used passwords, estimates entropy, gives rough brute-force crack times, and suggests improvements.

```bash
python3 passcheck.py
```

Example output:

```
score: 23/100 (weak)
entropy: ~28.5 bits (rough estimate)

estimated brute-force time (rough, assumes random password):
  online (throttled login): ~8 centuries
  offline (fast hash, one GPU): instantly

issues:
  - this is one of the most commonly used passwords — attackers try it first
  - too short (8 chars)

suggestions:
  - pick something that isn't on every leaked list
  - mix in uppercase, digits, symbols
```

The crack-time numbers assume a random password — real attackers use dictionaries and patterns, so treat them as optimistic. The common-password list (`common_passwords.txt`) is compiled from well-known public breach datasets and is only ever read locally.

## Running the tests

```bash
pip install -r requirements.txt
python3 -m pytest tests/ -v
```

## What's in here

- `port_scout.py` — the scanner
- `passcheck.py` — the password checker
- `common_passwords.txt` — public common-password list for local checking
- `tests/` — pytest suite (port tests use loopback only)

## Things I'd improve

- port-scout: send protocol-specific probes (like an HTTP GET) instead of only listening for banners — done Nov 2026 (sends `GET /` on quiet plain-HTTP ports; TLS ports left alone); add UDP support
- passcheck: check for l33t-speak variants of common passwords — done Oct 2026 (normalizes `@4$013!+|` etc. before checking the list)

## License

MIT — see LICENSE.
