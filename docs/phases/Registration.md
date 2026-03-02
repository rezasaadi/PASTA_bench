
This document specifies **PASTA registration** as two algorithms:
- `SignUp` (run by the client),
- `Store` (run by each server).


---

## 0. Purpose of registration in PASTA

Registration installs, at each server `Si`, a **per-client record** that enables:
- secure, two-round password verification *without server-side password hashes*, and
- threshold token issuance only when the client knows the correct password.

The client keeps **only the password** long-term.

---

## 1. Notation

- `C`: client identifier (username)
- `pwd ∈ P`: client password
- `i ∈ [n]`: server index
- `||`: concatenation
- `H(·)`: hash (random oracle in proofs)

The protocol derives a shared password-dependent value `h` (computed via TOPRF), and then
derives **server-specific keys** `hi`:

> `hi := H(h || i)`

This “index binding” is crucial: compromising one server reveals only its `hi`, not a universal key usable to decrypt other servers’ ciphertexts.

---

## 2. Algorithm: SignUp

### `SignUp(C, pwd) → ((C, msg1), …, (C, msgn))`

**Client inputs**
- Identifier `C`
- Password `pwd`

**Steps**
1. Generate a fresh per-client TOPRF key shared among servers:
   - `(⟨k⟩, opp) ← TOP.Setup(1^κ, n, t)`
   - Here `⟨k⟩ = (k1, …, kn)` are TOPRF key shares (one per server).
2. Compute the TOPRF output on the password:
   - `h := TOP(k, pwd)`
3. Derive a distinct per-server encryption key:
   - For each server index `i ∈ [n]`, compute:
     - `hi := H(h || i)`
4. Prepare one message per server:
   - For each `i ∈ [n]`, set:
     - `msgi := (ki, hi)`

**Output**
- The list of messages `((C, msg1), …, (C, msgn))`
- The client sends `(C, msgi)` to server `Si` for each `i`.

---

## 3. Algorithm: Store

### `Store(SKi, C, msgi) =: reci,C`

**Server inputs**
- Server identity/index `i` (implicit)
- Client identifier `C`
- Message `msgi = (ki, hi)`

**Steps**
1. Parse `msgi` as `(ki, hi)`
2. Create the record:
   - `reci,C := (ki, hi)`
3. Store `(C, reci,C)` in the server’s record database (if no record exists for `C` already).

**Server state after registration**
- Each server `Si` stores, for client `C`:
  - `ki`: its share of the client’s TOPRF key
  - `hi`: a per-server key derived from the password TOPRF output

---

## 4. Security intuition (registration-side)

PASTA avoids server-stored password hashes. Instead:
- Servers store `hi` values that depend on the password **and** a TOPRF key share.
- An attacker who breaches fewer than `t` servers cannot compute `h = TOP(k, pwd)` for guessed passwords offline.
- Per-server derivation `hi = H(h || i)` prevents “steal one server → impersonate client” attacks across the remaining servers.

Registration is typically assumed to use a secure channel (e.g., TLS), but it is a one-time cost and not on the critical sign-on path.
