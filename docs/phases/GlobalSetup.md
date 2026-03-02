### Parties
- **Client**: `C` (a user identifier; e.g., username).
- **Identity servers**: `S1, …, Sn` (threshold system).
- **Service providers / application servers**: verify tokens using a verification key.

### Threshold parameters
- `n`: number of identity servers  
- `t`: threshold, where `2 ≤ t ≤ n`  
- The client contacts any set `T ⊆ [n]` with `|T| ≥ t` to sign on.

### Password space
- `P`: password dictionary/space (modeled as uniform in the paper’s definitions, but the protocol itself does not require uniformity).

---

## 1. Building blocks used by PASTA

PASTA is black-box over these primitives:

### 1.1 Threshold Token Generation (TTG)
A threshold signature/MAC-like primitive:
- `TTG.Setup(1^κ, n, t) → (⟨sk⟩, vk, tpp)`
- `TTG.PartEval(ski, m) → yi`
- `TTG.Combine({(i, yi)}_{i∈T}) → tk`
- `TTG.Verify(vk, m, tk) → {0,1}`

Intuition: any `t` servers can generate a token/signature on message `m`, but fewer cannot.

### 1.2 Threshold Oblivious PRF (TOPRF), denoted TOP
A threshold OPRF used to derive a password-dependent secret `h` without allowing offline dictionary attacks after server compromise:
- `TOP.Setup(1^κ, n, t) → (⟨k⟩, opp)`
- `TOP.Encode(pwd, ρ) → c`
- `TOP.Eval(ki, c) → zi`
- `TOP.Combine(pwd, {(i, zi)}_{i∈T}, ρ) → h`

### 1.3 Symmetric-key encryption SKE
- `SKE.Encrypt(key, plaintext) → ciphertext`
- `SKE.Decrypt(key, ciphertext) → plaintext/⊥`

**Required property:** *key-binding* (decrypting with the wrong key fails with high probability).

### 1.4 Hash function H
- `H(·)` is modeled as a random oracle in the security proof.
- Used to derive **per-server** encryption keys from a shared `h`.

---

## 2. Phase 1: GlobalSetup

### Goal
Initialize:
- threshold token-generation shares for servers, and
- public parameters for the system.

### Algorithm: `GlobalSetup(1^κ, n, t, P) → (⟨sk⟩, vk, pp)`

**Input**
- Security parameter `κ`
- `n` servers, threshold `t`
- Password space `P`

**Steps**
1. Run threshold token setup:
   - `(⟨tsk⟩, tvk, tpp) ← TTG.Setup(1^κ, n, t)`
2. Assign each server’s long-term signing share:
   - For each `i ∈ [n]`, set `ski := tski`
3. Set the system verification key:
   - `vk := tvk`
4. Publish system parameters:
   - `pp := (κ, n, t, P, tpp)`

**Outputs**
- Servers hold: `(ski, pp)` for each `Si`
- Verifiers (application servers) hold: `(vk, pp)` (and can check tokens)
- Clients need: server identities/addresses + `pp` (public)


