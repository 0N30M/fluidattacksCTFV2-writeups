# Deadbolt — Deterministic Device Key and Admin Vault Bypass

- Name: Deadbolt  
- Category: Mobile  
- Difficulty: Hard  

In **Deadbolt**, we attack FluidVault, a mobile password manager that claims strong crypto (AES‑256‑GCM, PBKDF2) and biometric auth, but hides a fatal flaw in how it derives its vault key. Once we understand the key derivation and the weak device‑ID fallback, we can recover the admin master password from the encrypted backup and then call the server’s admin API using a simple HTTP request.

---

## 1. Challenge Overview

Provided artifacts (inside `public.zip`, password `infected`):

- Decompiled Android sources for the FluidVault app:
  - `com.fluidvault.crypto.CryptoManager`
  - `com.fluidvault.auth.BiometricAuthManager`
  - `com.fluidvault.data.VaultContentProvider`
  - `com.fluidvault.network.VaultApiClient`
  - `com.fluidvault.ui.LoginActivity`
- `vault_backup.enc` — encrypted vault backup.
- `vault_decrypt.py` — helper script that takes a 64‑char hex key and decrypts the backup using AES‑256‑GCM.

We never need a real device or emulator. The entire attack is:

1. Reconstruct how the vault key is derived.
2. Notice that the “device identifier” fallback makes the key deterministic.
3. Use the derived key to decrypt `vault_backup.enc` and recover the admin master password.
4. Send that password to the server’s admin API to get the flag.

---

## 2. CryptoManager and Key Derivation

### 2.1 PBKDF2 Parameters

From `CryptoManager.java`:

```java
private static final String SEED = "fluidvault_master_seed_2026";
private static final byte[] SALT = hexToBytes("a915c3e00dbb5a55ba13d7cdaf3a126e");
private static final int ITERATIONS = 10000;
private static final int KEY_LENGTH = 256; // bits
private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";

public static SecretKey deriveKey(String passphrase) {
    PBEKeySpec spec = new PBEKeySpec(passphrase.toCharArray(), SALT, ITERATIONS, KEY_LENGTH);
    SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
    return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
}
```

So the vault key is generated via PBKDF2‑HMAC‑SHA256:

- Seed: `fluidvault_master_seed_2026`
- Salt: `a915c3e00dbb5a55ba13d7cdaf3a126e` (16 bytes)
- Iterations: 10,000
- Key length: 256 bits (32 bytes)

The missing piece is: **what passphrase** is fed into this KDF?

### 2.2 Device Identifier and Passphrase Assembly

`getDeviceIdentifier()`:

```java
public static String getDeviceIdentifier() {
    String serial = Build.SERIAL;
    if (serial == null || serial.equals("unknown")) {
        serial = "DEFAULT_DEVICE_ID";
    }
    return Integer.toHexString(serial.hashCode());
}
```

`getVaultKey()`:

```java
public static SecretKey getVaultKey() {
    String deviceId = getDeviceIdentifier();
    String passphrase = SEED + deviceId;
    return deriveKey(passphrase);
}
```

So the passphrase is:

```text
passphrase = "fluidvault_master_seed_2026" + Integer.toHexString(Build.SERIAL.hashCode())
```

On a real device, `Build.SERIAL` is hardware‑specific, making the key per‑device. But in this challenge context (emulator / environment where `Build.SERIAL` is `"unknown"` or `null`), the app falls back to a **hardcoded serial**:

```java
serial = "DEFAULT_DEVICE_ID";
```

This is the core bug: the key becomes fully deterministic and identical everywhere.

---

## 3. Computing the Correct Passphrase

A subtle but important detail: the app does **not** append `"DEFAULT_DEVICE_ID"` directly. It appends:

```text
Integer.toHexString(serial.hashCode())
```

We must replicate Java’s `String.hashCode()` exactly, not use Python’s `hash()`.

### 3.1 Java `String.hashCode()` Logic

In pseudocode:

```python
def java_string_hashcode(s: str) -> int:
    h = 0
    for c in s:
        h = (31 * h + ord(c)) & 0xFFFFFFFF
    if h >= 0x80000000:
        h -= 0x100000000
    return h

def int_to_hex_string(h: int) -> str:
    return format(h & 0xFFFFFFFF, 'x')
```

Applying it to `"DEFAULT_DEVICE_ID"`:

- `java_string_hashcode("DEFAULT_DEVICE_ID")` → some signed 32‑bit integer (e.g. `-924706042`).
- `Integer.toHexString(hash)` → the hex representation of that integer’s 32‑bit value:

```text
deviceId = "c8e21b06"
```

The **correct passphrase** is:

```text
fluidvault_master_seed_2026c8e21b06
```

Common mistake: using `"DEFAULT_DEVICE_ID"` directly in the passphrase, which does **not** match the app’s key derivation.

### 3.2 Deriving the AES Key

Using PBKDF2‑HMAC‑SHA256 with:

- Passphrase: `fluidvault_master_seed_2026c8e21b06`
- Salt: `a915c3e00dbb5a55ba13d7cdaf3a126e`
- Iterations: 10,000
- Output length: 32 bytes

We obtain a 256‑bit AES key (hex string) that we feed into `vault_decrypt.py` to decrypt `vault_backup.enc`.

---

## 4. Vault Backup Format and Decryption

`vault_backup.enc` structure:

- First 12 bytes: IV for AES‑GCM.
- Remaining bytes: ciphertext + 16‑byte GCM tag.

`CryptoManager.encrypt()` confirms:

```java
private static final int GCM_IV_LENGTH = 12;
private static final int GCM_TAG_LENGTH = 128; // bits

public static byte[] encrypt(byte[] plaintext, SecretKey key) {
    byte[] iv = new byte[GCM_IV_LENGTH];
    secureRandom.nextBytes(iv);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key,
        new GCMParameterSpec(GCM_TAG_LENGTH, iv));
    byte[] ciphertext = cipher.doFinal(plaintext);
    return concat(iv, ciphertext); // prepend IV
}
```

So decryption is:

1. Read IV = first 12 bytes.
2. Read ciphertext+tag = rest.
3. Decrypt with AES‑256‑GCM using the derived key and IV.

After decryption, the plaintext is a JSON vault:

```json
{
  "version": 2,
  "created": "2026-03-15T09:22:41Z",
  "entries": [
    {
      "id": 1,
      "name": "Admin Portal",
      "username": "admin",
      "password": "Fl00d_G4t3s_0p3n!",
      "url": "https://vault.internal.fluidvault.io/admin",
      "notes": "Master admin - DO NOT SHARE"
    },
    ...
  ]
}
```

The first entry (`Admin Portal`) contains the **master admin password**:

```text
Fl00d_G4t3s_0p3n!
```

This is what we need to authenticate to the server’s admin API.

---

## 5. Server API and My Exploit Request

From `VaultApiClient.java`:

```java
public class VaultApiClient {
    public VaultInfo getVaultInfo() { /* GET /api/vault/info */ }
    public AuthResult submitAdminAuth(String masterPassword) {
        // POST /api/vault/admin
        // Body: {"master_password":"<password>"}
    }
}
```

Recon on the API shows:

- `GET /` — basic service info.
- `GET /api/vault/info` — confirms algorithm (AES‑256‑GCM, PBKDF2, iterations).
- `POST /api/vault/admin` — accepts JSON `{"master_password": "..."}`
  - Returns 401 for wrong password.
  - Returns 200 and flag for correct password.

Once we have the admin master password from the decrypted vault, the final step is just an HTTP POST.

Here is the exact command I used:

```bash
curl -sk -X POST 'TUHOST/api/vault/admin' \
  -H 'Content-Type: application/json' \
  --data '{"master_password":"Fl00d_G4t3s_0p3n!"}' \
| jq
```

Explanation:

- `TUHOST` — replace with the challenge host you were given.
- `-X POST` — POST request to `/api/vault/admin`.
- `Content-Type: application/json` — JSON body.
- Body: `"master_password"` set to the value obtained from the decrypted vault.
- Pipe to `jq` to pretty‑print the JSON response.

The server responds with JSON indicating that authentication succeeded and includes the flag in the admin response.

---

## 6. Lessons Learned

### 6.1 Weak Fallbacks Break Strong Crypto

Deadbolt uses solid primitives:

- AES‑256‑GCM for confidentiality and integrity.
- PBKDF2‑HMAC‑SHA256 with a reasonable iteration count.

However, the **key derivation input** is flawed:

- When `Build.SERIAL` is unavailable, the app uses `"DEFAULT_DEVICE_ID"` and derives the key from a known constant.
- This makes the key predictable, static, and identical across devices.
- Strong crypto with a predictable key is effectively **no security**.

A more secure design would:

- Refuse to operate if the device ID is unavailable (fail closed).
- Use hardware‑backed keystores and per‑device secrets.
- Avoid hardcoded identifiers for key material.

### 6.2 Java Hash Semantics Matter

The challenge also hinges on understanding:

- Java’s `String.hashCode()` algorithm (polynomial hash with multiplier 31).
- Its signed 32‑bit behavior and how `Integer.toHexString()` exposes it.
- The difference between using the raw serial string versus `hex(hashCode(serial))`.

Getting the passphrase slightly wrong (e.g., using `"DEFAULT_DEVICE_ID"` instead of `"c8e21b06"`) leads to the wrong key and failed decryption.

### 6.3 Defense in Depth on the Server Side

Even after decryption:

- The server still requires **master_password** to be correct for `/api/vault/admin`.
- There is no additional client‑side secret; the password alone gates admin access.

If the vault backup leaks and the key can be derived deterministically, the admin password becomes known, and server authentication is trivially bypassed.

---

## 7. Summary of Attack Chain

1. Extract and analyze `CryptoManager.java` to understand key derivation.
2. Notice the `DEFAULT_DEVICE_ID` fallback in `getDeviceIdentifier()`.
3. Implement Java’s `hashCode()` to compute the correct device ID hex.
4. Build the PBKDF2 passphrase: `fluidvault_master_seed_2026<deviceIdHex>`.
5. Use PBKDF2‑HMAC‑SHA256 with the known salt and iterations to derive the AES‑256 key.
6. Decrypt `vault_backup.enc` with AES‑GCM to recover the vault JSON.
7. Extract the admin master password `Fl00d_G4t3s_0p3n!`.
8. Send a POST request to `/api/vault/admin` with that password:

   ```bash
   curl -sk -X POST 'TUHOST/api/vault/admin' \
     -H 'Content-Type: application/json' \
     --data '{"master_password":"Fl00d_G4t3s_0p3n!"}' | jq
   ```

9. Read the flag from the JSON response.

Deadbolt is a perfect illustration that **crypto code can be correct, but still broken in practice** when it’s wired to predictable, hardcoded inputs.
