# Crumble Cookie — SHA-256 Length Extension Attack

- Challenge: Crumble Cookie  
- Category: Cryptography  
- Difficulty: Easy  
- Target: `https://9483f940239b8f2a.chal.ctf.ae`  
- Flag: `flag{bedfafcfca914200}`  

This writeup explains how I solved **Crumble Cookie** by abusing a SHA-256 length extension vulnerability in the file download token mechanism, using a custom Python exploit script.

---

## 1. Challenge Description

The challenge exposes a Flask-based API called **SecureVault File Sharing**, which provides cryptographically signed download links for files.  
Each downloadable file has a `token` and a corresponding `sig` (signature) computed on the server using a secret key.

The key points:

- There is a special file: `private/flag.txt` that contains the flag.
- No signed token for `private/flag.txt` is ever returned by the API.
- Our goal is to **forge** a valid `(token, sig)` pair that requests `private/flag.txt` and passes the server-side signature check.

---

## 2. Reconnaissance

### Endpoints Discovered

| Endpoint   | Method | Description                                       |
|-----------|--------|---------------------------------------------------|
| `/`       | GET    | Service info and API version                      |
| `/files`  | GET    | Lists public files with signed tokens             |
| `/download` | GET  | Downloads a file using a signed token             |
| `/health` | GET    | Health check endpoint                             |

### API Structure

`GET /` returns something like:

```json
{
  "service": "SecureVault File Sharing API",
  "version": "1.2.0",
  "endpoints": {
    "/files": "List available files with signed download tokens",
    "/download": "Download a file using a signed token"
  }
}
```

`GET /files` returns a list of public files, each with a signed token:

```json
{
  "files": [
    {
      "path": "public/notes.txt",
      "token": "action=download&file=public/notes.txt",
      "sig": "41f55a0b9d9266ada1dee2e3fe2fd236cc0491fff56c22700b4d2bc858ba6a66",
      "download": "/download?token=action%3Ddownload%26file%3Dpublic%2Fnotes.txt&sig=41f55a0b9d9266ada1dee2e3fe2fd236cc0491fff56c22700b4d2bc858ba6a66"
    },
    {
      "path": "public/welcome.txt",
      "token": "action=download&file=public/welcome.txt",
      "sig": "eb98dbd9635899e1e02a493d7a1e067b540dc3653c8959099fb62f8e44a439fd",
      "download": "/download?token=action%3Ddownload%26file%3Dpublic%2Fwelcome.txt&sig=eb98dbd9635899e1e02a493d7a1e067b540dc3653c8959099fb62f8e44a439fd"
    }
  ]
}
```

`GET /download?token=<urlencoded>&sig=<hex>`:

- Verifies the signature.
- If valid, parses the `token` to find the `file` parameter.
- If `file` is `private/flag.txt`, it returns the flag.

### Known Valid Token/Signature Pairs

| Token                                        | Signature                                                         |
|---------------------------------------------|-------------------------------------------------------------------|
| `action=download&file=public/notes.txt`     | `41f55a0b9d9266ada1dee2e3fe2fd236cc0491fff56c22700b4d2bc858ba6a66` |
| `action=download&file=public/welcome.txt`   | `eb98dbd9635899e1e02a493d7a1e067b540dc3653c8959099fb62f8e44a439fd` |

### Hints in the Challenge

- Challenge name **“Crumble Cookie”** suggests the signing scheme will *crumble* under a hash-based attack.
- `public/notes.txt` contains hints like:
  - “Migrate API auth to HMAC-based tokens”
  - “Update signing mechanism (pending)”
- Source comments mention a **16-character API key**, leaking the key length (16 bytes), which is very useful for a length extension attack.

---

## 3. Source Code Analysis

The provided `app.py` (inside a protected archive) contains the relevant logic.

### Signing Function

```python
def sign(message_bytes):
    """Sign a message using SHA256(SECRET_KEY + message)."""
    return hashlib.sha256(SECRET_KEY.encode() + message_bytes).hexdigest()
```

The server uses the naïve construction:

- `SHA256(secret || message)`

This is exactly the pattern vulnerable to **hash length extension** for Merkle–Damgård hashes like SHA-256.

### Token Parser

```python
def parse_token_params(token_bytes):
    """Parse key=value pairs separated by '&' from token bytes."""
    parts = {}
    try:
        token_str = token_bytes.decode("latin-1")
    except Exception:
        return parts

    for segment in token_str.split("&"):
        if "=" in segment:
            key, _, value = segment.partition("=")
            parts[key] = value
    return parts
```

Important behavior:

- Splits on `&`.
- Inserts `key=value` into a dictionary.
- **Last value wins**: if the token has `file=X&file=Y`, then `file` ends up as `Y`.

This allows us to keep an original, valid `file=public/...` and later override it with `file=private/flag.txt`.

### Download Endpoint

```python
@app.route("/download")
def download():
    token = request.args.get("token", "")
    sig = request.args.get("sig", "")

    if not token or not sig:
        return jsonify({"error": "Missing token or sig parameter"}), 400

    token_bytes = token.encode("latin-1")

    expected_sig = sign(token_bytes)
    if sig != expected_sig:
        return jsonify({"error": "Invalid signature"}), 403

    params = parse_token_params(token_bytes)
    filepath = params.get("file")

    if not filepath:
        return jsonify({"error": "No file specified in token"}), 400

    if filepath == "private/flag.txt":
        return jsonify({
            "filename": "private/flag.txt",
            "content": FLAG,
        })

    if filepath in FILES:
        return jsonify({
            "filename": filepath,
            "content": FILES[filepath],
        })

    return jsonify({"error": "File not found"}), 404
```

Key observations:

- The signature is computed **directly** over the `token` bytes.
- The check uses `SHA256(secret || token)` and compares it with `sig`.
- Only after signature verification, the token is parsed to extract `file`.
- If `file == "private/flag.txt"`, the server returns the flag.

So the only barrier to the flag is producing a `(token, sig)` pair that passes `sign(token) == sig` and contains `file=private/flag.txt` as the final `file` parameter.

---

## 4. Vulnerability: SHA-256 Length Extension

### Merkle–Damgård and Length Extension

SHA-256 is a Merkle–Damgård hash:

- It processes data in 512-bit (64-byte) blocks.
- It maintains an internal state (eight 32-bit words).
- After processing the last block, the final state is output as the 256-bit hash.

Critical consequence:

- The hash output is literally the internal state after processing the last block.
- If you know `SHA256(secret || message)`, you know the internal state after processing `secret || message || padding`.

From that state, you can **resume** hashing new data:

- Compute `SHA256(secret || message || padding || extra)`  
- Without ever knowing `secret`.

### Why `SHA256(secret || message)` is Dangerous

This construction is vulnerable because:

- The output hash exposes the internal state.
- The padding is deterministic and depends only on the total length.
- The attacker knows:
  - `message` (public token),
  - key length (16 bytes, from the hint),
  - and the digest `SHA256(secret || message)`.

That’s enough to:

1. Reconstruct internal state from the digest.
2. Compute the padding for `secret || message`.
3. Continue hashing `extra_data`.

### Why HMAC Avoids This

HMAC uses a more complex construction, e.g.:

```text
HMAC(K, m) = SHA256((K' ⊕ opad) || SHA256((K' ⊕ ipad) || m))
```

The inner hash state is wrapped by an outer hash; length extension on the inner hash does not give a valid overall MAC. This is why `notes.txt` recommends moving to HMAC-based tokens.

---

## 5. Attack Strategy (Using My Script)

Instead of calculating everything manually, I wrote a script that:

1. Fetches all public tokens from `/files`.
2. For each `(token, sig)` pair, tries multiple possible secret lengths.
3. For each candidate length, performs a SHA-256 length extension:
   - Rebuilds internal state from `sig`.
   - Applies SHA-256 padding as if the server had hashed `secret || token`.
   - Appends `&file=private/flag.txt`.
4. Encodes the forged token with URL-safe encoding, preserving binary padding bytes.
5. Sends `GET /download?token=<forged>&sig=<forged_sig>`.
6. Extracts the flag from the response.

This general approach makes the exploit reusable for similar challenges where the secret length is unknown but bounded.

---

## 6. Exploit Script (My Version)

Here is the script I used, adapted for the challenge, and designed to iterate over all public tokens and a range of possible secret lengths:

```python
#!/usr/bin/env python3
import json
import re
import ssl
import struct
import urllib.request
import urllib.parse
import urllib.error

# ==========================================================
# EDIT THESE 2 LINES BEFORE USING IT
# ==========================================================

HOST = "https://9483f940239b8f2a.chal.ctf.ae"
TARGET_FILE = "private/flag.txt"

# ==========================================================
# DO NOT TOUCH BELOW THIS LINE
# ==========================================================

MAX_SECRET_LEN = 128

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


def ror(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def sha256_padding(message_len):
    return (
        b"\x80"
        + b"\x00" * ((56 - (message_len + 1) % 64) % 64)
        + struct.pack(">Q", message_len * 8)
    )


def sha256_compress(chunk, h):
    w = list(struct.unpack(">16I", chunk)) +  * 48

    for i in range(16, 64):
        s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff

    a, b, c, d, e, f, g, hh = h

    for i in range(64):
        S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (hh + S1 + ch + K[i] + w[i]) & 0xffffffff

        S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xffffffff

        hh = g
        g = f
        f = e
        e = (d + temp1) & 0xffffffff
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xffffffff

    return [
        (h + a) & 0xffffffff,
        (h + b) & 0xffffffff,[1]
        (h + c) & 0xffffffff,[2]
        (h + d) & 0xffffffff,[3]
        (h + e) & 0xffffffff,[4]
        (h + f) & 0xffffffff,[5]
        (h + g) & 0xffffffff,[6]
        (h + hh) & 0xffffffff,[7]
    ]


def sha256_length_extend(original_sig, extra_data, processed_len):
    h = list(struct.unpack(">8I", bytes.fromhex(original_sig)))

    final_data = extra_data + sha256_padding(processed_len + len(extra_data))

    for i in range(0, len(final_data), 64):
        h = sha256_compress(final_data[i:i + 64], h)

    return "".join(f"{x:08x}" for x in h)


def fetch(url):
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0",
        },
    )

    with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
        return r.status, r.read().decode(errors="replace")


def get_error_body(e):
    try:
        return e.read().decode(errors="replace")
    except Exception:
        return str(e)


def main():
    host = HOST.rstrip("/")

    if not host.startswith("http"):
        print("[-] HOST must start with http:// or https://")
        return

    print("[+] SecureVault exploit")
    print(f"[+] Host: {host}")
    print(f"[+] Target file: {TARGET_FILE}")
    print()

    try:
        code, body = fetch(host + "/files")
        data = json.loads(body)
    except Exception as e:
        print(f"[-] Could not read /files: {e}")
        return

    files = data.get("files", [])

    if not files:
        print("[-] No public tokens found in /files")
        print(body)
        return

    print(f"[+] Tokens found: {len(files)}")

    append_data = f"&file={TARGET_FILE}".encode("latin-1")

    for item in files:
        original_token = item.get("token", "")
        original_sig = item.get("sig", "")

        if not original_token or not original_sig:
            continue

        print()
        print("[+] Trying base token:")
        print(f"    token = {original_token}")
        print(f"    sig   = {original_sig}")

        original_token_bytes = original_token.encode("latin-1")

        for secret_len in range(1, MAX_SECRET_LEN + 1):
            glue_padding = sha256_padding(secret_len + len(original_token_bytes))

            forged_token = original_token_bytes + glue_padding + append_data

            processed_len = secret_len + len(original_token_bytes) + len(glue_padding)

            forged_sig = sha256_length_extend(
                original_sig,
                append_data,
                processed_len,
            )

            # IMPORTANT:
            # Flask receives the token as UTF-8 text.
            # To preserve bytes like 0x80, 0xa8, etc.,
            # we convert bytes to latin-1 and then URL-encode.
            forged_token_text = forged_token.decode("latin-1")
            encoded_token = urllib.parse.quote(forged_token_text, safe="")

            exploit_url = f"{host}/download?token={encoded_token}&sig={forged_sig}"

            try:
                status, response = fetch(exploit_url)
            except urllib.error.HTTPError as e:
                status = e.code
                response = get_error_body(e)
            except Exception:
                continue

            if status == 403:
                continue

            print()
            print(f"[+] Request accepted with secret_len={secret_len}")
            print(f"[+] HTTP status: {status}")
            print()
            print("[+] Raw response:")
            print(response)
            print()

            try:
                parsed = json.loads(response)
                if isinstance(parsed, dict) and "content" in parsed:
                    print("[+] FILE CONTENT:")
                    print(parsed["content"])
                    return
            except Exception:
                pass

            match = re.search(r"[A-Za-z0-9_]+\{[^}]+\}", response)

            if match:
                print("[+] FLAG FOUND:")
                print(match.group(0))
                return

            print("[!] Request was accepted, but the flag could not be automatically extracted.")
            return

    print()
    print("[-] Exploit did not work.")
    print("[-] Check HOST and TARGET_FILE.")
    print("[-] For this challenge, TARGET_FILE is typically: private/flag.txt")


if __name__ == "__main__":
    main()
```

---

## 7. How My Script Differs and What It Adds

Compared to a single-message, one-shot exploit script:

- **Generic host support**: you can plug in any challenge host and reuse the logic.
- **Iterates over all public tokens**: if multiple tokens exist, any of them can serve as a base.
- **Brute-force secret length**: instead of relying on a hard-coded key length, the script tries all lengths up to `MAX_SECRET_LEN` (128), making it robust against minor variations.
- **Response parsing**:
  - Tries to parse JSON and show `"content"` if present.
  - Falls back to a regex that matches typical `FLAG{...}` patterns.
- **Clear error handling**: distinguishes `403` (invalid MAC) from other HTTP errors and prints helpful messages.
- **Binary-safe URL encoding**: ensures padding bytes survive Flask’s UTF-8 treatment by decoding as Latin-1 first.

This keeps the exploit logic original while still following the same underlying cryptographic idea.

---

## 8. Exploit Execution

With `HOST` set to the challenge URL:

1. Run the script.
2. It fetches `/files` and prints the number of tokens.
3. For each token:
   - Tries secret lengths from 1 to 128.
   - Builds forged tokens and signatures.
   - Sends them to `/download`.
4. Once a valid `(token, sig)` is found, the server responds with either:
   - JSON containing `"filename": "private/flag.txt", "content": "flag{...}"`, or
   - A raw flag string that matches the regex.

For the Crumble Cookie instance, the server returned:

```json
{
  "content": "flag{bedfafcfca914200}",
  "filename": "private/flag.txt"
}
```

---

## 9. Lessons Learned

### Why HMAC Is Required

Using `SHA256(secret || message)` as a MAC is fundamentally flawed for Merkle–Damgård hashes.  
The correct construction is HMAC:

```python
import hmac, hashlib

def sign(message_bytes):
    return hmac.new(SECRET_KEY.encode(), message_bytes, hashlib.sha256).hexdigest()
```

HMAC prevents length extension because the inner hash state is rehashed with a different key-derived block, and the final MAC cannot be forged just from the inner digest.

### Core Ideas of the Length Extension Attack

- The hash output **is** the internal state.
- Padding is deterministic and depends only on the total length.
- An attacker who knows:
  - Hash of `secret || message`,
  - Length of `secret`,
  - The `message` itself,
  can:
  - Recreate the correct padding for `secret || message`,
  - Resume hashing new data,
  - Produce a valid hash for `secret || message || padding || extra`.
- The secret key itself is never recovered—just **bypassed**.

---
