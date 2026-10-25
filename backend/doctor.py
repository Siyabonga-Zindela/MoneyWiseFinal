"""MoneyWise local setup doctor.

Run from the backend folder (or anywhere):

    python doctor.py          # diagnose only
    python doctor.py --fix    # also apply the safe auto-fixes (sslmode append)

Plain stdlib + psycopg2: it never imports the app, so it works even when the
app itself cannot start. It checks, in order:

  1. backend/.env exists (and is not accidentally named .env.txt)
  2. DATABASE_URL inside it is well-formed and not left as a placeholder
  3. sslmode=require is present (Neon only accepts TLS connections)
  4. no shell environment variable is overriding the .env value
     (pydantic-settings prefers real env vars over the .env file)
  5. a real connection to the database succeeds
  6. the existing schema is readable (SELECT count(*) FROM users)

Exit codes: 0 = all good, 1 = configuration problem, 2 = database unreachable.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from urllib.parse import quote, urlsplit

BACKEND_DIR = Path(__file__).resolve().parent
ENV_PATH = BACKEND_DIR / ".env"

OK = "[OK]"
BAD = "[FIX]"
WARN = "[!!]"

PLACEHOLDER_RE = re.compile(r"YOUR_NEON|<|>|change-?me", re.IGNORECASE)


def line(text: str = "") -> None:
    print(text)


def masked_url(raw: str) -> str:
    """scheme://user:***@host:port/db?params - never prints the password."""
    try:
        parts = urlsplit(raw)
        host = parts.hostname or "?"
        port = f":{parts.port}" if parts.port else ""
        return f"{parts.scheme}://{parts.username}:***@{host}{port}{parts.path}"
    except Exception:  # noqa: BLE001 - masking must never crash
        return "(unparseable URL)"


def load_env_file() -> dict[str, str]:
    values: dict[str, str] = {}
    if not ENV_PATH.exists():
        return values
    for raw_line in ENV_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
        text = raw_line.strip()
        if not text or text.startswith("#") or "=" not in text:
            continue
        key, _, value = text.partition("=")
        value = value.strip().strip('"').strip("'")
        values[key.strip()] = value
    return values


def check_env_file() -> tuple[str | None, list[str]]:
    """Returns (database_url or None, notes)."""
    notes: list[str] = []

    if not ENV_PATH.exists():
        notes.append(f"{BAD} backend/.env NOT FOUND at: {ENV_PATH}")
        txt_variant = BACKEND_DIR / ".env.txt"
        if txt_variant.exists():
            notes.append(
                f"{BAD} Found backend/.env.txt - Windows Notepad appended .txt."
                " Rename it to exactly .env (no extension)."
            )
        root_env = BACKEND_DIR.parent / ".env"
        if root_env.exists():
            notes.append(
                f"{BAD} Found a .env in the PROJECT ROOT ({root_env}) - the app only"
                f" reads backend/.env. Move it to {ENV_PATH}."
            )
        notes.append(
            "     Create the file backend/.env with your Neon connection string:"
            "  DATABASE_URL=postgresql://USER:PASSWORD@HOST/neondb?sslmode=require"
        )
        return None, notes

    notes.append(f"{OK} backend/.env found at {ENV_PATH}")

    env = load_env_file()
    raw = env.get("DATABASE_URL", "")
    if not raw:
        notes.append(f"{BAD} .env has no DATABASE_URL line at all")
        return None, notes

    if "\r" in raw:
        notes.append(f"{BAD} DATABASE_URL contains a Windows carriage return (\\r).")
        notes.append("     Re-save backend/.env with Unix (LF) line endings or run: python doctor.py --fix")
    if raw != raw.strip():
        notes.append(f"{WARN} DATABASE_URL has leading/trailing spaces - they will be stripped.")
        raw = raw.strip()

    if PLACEHOLDER_RE.search(raw):
        notes.append(f"{BAD} DATABASE_URL still contains a placeholder: {masked_url(raw)}")
        notes.append("     Replace YOUR_NEON_USER / YOUR_NEON_PASSWORD with the real values from the Neon dashboard.")
        return None, notes

    parts = urlsplit(raw)
    if parts.scheme not in ("postgres", "postgresql"):
        notes.append(
            f"{BAD} DATABASE_URL must start with postgresql:// (found: {parts.scheme or 'nothing'}://)"
        )
        return None, notes
    if not parts.hostname or not parts.username:
        notes.append(f"{BAD} DATABASE_URL is missing the host or user part: {masked_url(raw)}")
        return None, notes

    password = parts.password
    if password is None:
        notes.append(f"{BAD} DATABASE_URL has no password: {masked_url(raw)}")
        return None, notes
    if any(ch in password for ch in ":@/?#"):
        encoded = quote(password, safe="")
        notes.append(
            f"{WARN} The password contains special characters (: @ / ? #)."
            " If the connection fails with a parse or auth error, percent-encode it:"
        )
        notes.append(f"     password -> {encoded}")

    if "sslmode=" not in raw:
        notes.append(f"{WARN} DATABASE_URL has no sslmode=require - Neon REJECTS non-TLS connections.")
        notes.append("     Run  python doctor.py --fix  to append it automatically.")
    else:
        notes.append(f"{OK} sslmode is set")

    notes.append(f"{OK} URL structure looks valid: {masked_url(raw)}")
    return raw, notes


def check_shell_override() -> None:
    shell_value = os.environ.get("DATABASE_URL")
    if not shell_value:
        line(f"{OK} No shell DATABASE_URL variable overriding backend/.env")
        return
    line(f"{WARN} A DATABASE_URL environment variable IS set in this shell and it")
    line("     OVERRIDES backend/.env (pydantic-settings reads real env vars first).")
    line(f"     Its value: {masked_url(shell_value)}")
    line("     Fix: close the terminal and open a new one, or run:")
    line("          set DATABASE_URL=        (Windows CMD)   /   unset DATABASE_URL   (macOS/Linux)")


def probe_database(raw: str) -> int:
    try:
        import psycopg2  # noqa: PLC0415 - local import keeps --help fast
    except ImportError:
        line(f"{BAD} psycopg2 is not installed. Run:  pip install -r requirements.txt")
        return 1

    dsn = raw if "sslmode=" in raw else raw + ("&" if "?" in raw else "?") + "sslmode=require"
    line(f"     Connecting to {masked_url(dsn)} ...")
    try:
        conn = psycopg2.connect(dsn, connect_timeout=8)
    except psycopg2.OperationalError as exc:
        message = str(exc).strip().replace("\n", " | ")
        line(f"{BAD} CONNECTION FAILED: {message}")
        low = message.lower()
        if "connection refused" in low or "could not connect" in low:
            line("     -> The app is NOT talking to Neon. If it says 'localhost', your")
            line("        .env is not being used or still has the default value.")
        elif "password authentication failed" in low or "role" in low and "does not exist" in low:
            line("     -> Wrong user or password. Copy them again from the Neon dashboard")
            line("        (Connection Details -> copy the whole connection string).")
        elif "ssl" in low:
            line("     -> TLS is required but not negotiated. Run:  python doctor.py --fix")
        elif "name or service not known" in low or "getaddrinfo" in low or "resolve" in low:
            line("     -> The Neon hostname does not resolve. Re-copy the connection string;")
            line("        check your internet connection.")
        elif "timeout" in low or "timed out" in low:
            line("     -> Network is blocking port 5432. Try another network (corporate/eduroam")
            line("        wifi often blocks it) or a phone hotspot.")
        return 2

    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM users")
        users = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM risk_assessments")
        checks = cur.fetchone()[0]
    conn.close()
    line(f"{OK} CONNECTED - users table: {users} row(s), risk_assessments: {checks} row(s)")
    line("")
    line("Everything is configured correctly. Start the app with:")
    line("    cd backend")
    line("    python -m uvicorn app.main:app --port 8000")
    line("then open  http://localhost:8000  and run the checker.")
    return 0


def apply_fixes(env: dict[str, str]) -> None:
    raw = env.get("DATABASE_URL", "")
    if not raw or "sslmode=" in raw:
        line("Nothing to auto-fix.")
        return
    fixed = raw + ("&" if "?" in raw else "?") + "sslmode=require"
    content = ENV_PATH.read_text(encoding="utf-8", errors="replace")
    content = content.replace(f"DATABASE_URL={raw}", f"DATABASE_URL={fixed}")
    ENV_PATH.write_text(content, encoding="utf-8")
    line(f"{OK} Appended sslmode=require to DATABASE_URL in {ENV_PATH}")
    line(f"     New value: {masked_url(fixed)}")


def main() -> int:
    line("")
    line("=" * 64)
    line("MoneyWise local setup doctor")
    line("=" * 64)

    url, notes = check_env_file()
    for note in notes:
        line(note)
    if url is None:
        line("")
        line("Fix the items above, then run this script again.")
        return 1

    line("")
    check_shell_override()
    line("")
    code = probe_database(url)
    line("")
    return code


if __name__ == "__main__":
    env_data = load_env_file()
    if "--fix" in sys.argv:
        apply_fixes(env_data)
        line("")
    sys.exit(main())
