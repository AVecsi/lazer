# Falcon device binding — what the ZKP actually does

A plain-language companion to `falcon-devicebind-design.md`. It describes the
system implemented in `tests/fdb-test.c`: what is proven, who holds what, the
value types and where they live, and the message flow.

---

## 1. The one-sentence claim

> "The credential I hold is bound to a hardware key, and that same hardware key
> just signed your challenge — and I can prove both **without revealing the
> public key or the signature**."

Concretely, a Secure Element (SE) holds a **Falcon-512** key pair. A verifier
sends a fresh challenge `c`. The SE produces a short signature `(s1, s2)` such
that `s1 + s2·h = c (mod 12289)`, where `h` is the SE's public key. The user
then proves, in zero knowledge:

1. **Possession of a fresh valid signature:** it knows short `(s1, s2)` with
   `s1 + s2·h = c` — so the holder controls the SE right now (freshness comes
   from `c` being a nonce).
2. **The key is the committed one:** the `h` used above is exactly the public
   key committed inside the credential — proving the signature came from *this*
   device, not any device.

The verifier learns only **accept/reject** and its own challenge `c`. It never
sees `h` or `(s1, s2)`.

---

## 2. The actors and what each holds

| Actor | Holds (secret) | Holds (public) | Can do |
|-------|----------------|----------------|--------|
| **Secure Element (SE)** | Falcon secret key `sk` (1281 B) | its public key `h` (897 B encoded) | **only signs**: given `c`, returns short `(s1,s2)` with `s1+s2·h=c`. Never exports `sk`. |
| **User / prover** | the signature `(s1,s2)`, the key `h`, the quotient `k` | the credential, the challenge `c`, public params | asks the SE to sign, builds the ZK proof `π`. |
| **Credential** | — | a commitment that binds `h` (issued by an issuer) | — (data, not an actor) |
| **Verifier** | — | `c` (its own nonce), public params, the commitment | sends `c`, checks `π`, outputs accept/reject. |

The crucial trust split: **the SE only signs.** It does no zero-knowledge work
(SEs can't). All ZK proving happens on the user's device, over data the SE
handed out plus the credential.

---

## 3. Value types and where they live

Everything is polynomials over two related rings.

- **`RF` = Z₁₂₂₈₉[X] / (X⁵¹² + 1)** — the native Falcon ring (degree 512,
  modulus `p = 12289`). The public key `h`, challenge `c`, and signature
  `(s1, s2)` are elements of `RF`.
- **`Rp` = Z₁₂₂₈₉[X] / (X⁶⁴ + 1)** — degree 64, same modulus. lazer's proof
  machinery works over degree-64 rings, so every degree-512 object is carried
  as its **8-block isoring representation**: one `RF` element ⇔ eight `Rp`
  elements. Multiplication by `h` in `RF` becomes an **8×8 matrix `M_h`** over
  `Rp` (the block-negacyclic structure — its structure constants are ±1, which
  is what keeps the proof modulus small).
- **`Rq` = Z_q[X] / (X⁶⁴ + 1)** with `q ≈ 2⁵¹` — the *proof* ring. Much larger
  modulus than `p`, because the zero-knowledge arithmetic must not wrap.

| Value | Symbol | Type | Bound | Lives with | Secret? |
|-------|--------|------|-------|------------|---------|
| Falcon public key | `h` | `RF`, 8 `Rp` blocks | uniform mod p | SE (issued into credential) | **hidden** |
| Challenge | `c` | `RF` | in `[0,p)` | verifier → user | public |
| Signature part 1 | `s1` | `RF`, short | `‖(s1,s2)‖₂ ≤ β` (β²=34034726) | SE → user | **hidden** |
| Signature part 2 | `s2` | `RF`, short | (same joint bound) | SE → user | **hidden** |
| mod-p quotient | `k` | 8 `Rp` blocks | `‖k‖∞ ≤ B'` (=8958759, actual ≈3000) | computed by user | **hidden** |

`k` is a *helper witness*. Over the integers `s1 + s2·h − c` is not zero; it is
a multiple of `p`. Writing that multiple as `p·k` and proving `k` is small is
how the proof enforces the relation "mod p" inside the big ring `Rq`
(the "route-b" explicit quotient — needed because `s2·h` is a *quadratic* term
in two hidden values).

---

## 4. The zero-knowledge statement

Everything is lifted to the 8-block isoring rep and proven over `Rq`:

```
(1)  s1 + s2·h − c − p·k = 0        (8 block equations; the Falcon relation mod p)
(2)  ‖(s1, s2)‖₂ ≤ β                (the signature is genuinely short)
(3)  ‖k‖∞ ≤ B'                      (the quotient is small ⇒ (1) really holds mod p)
```

- Equation (1) is **quadratic**: `s2·h` couples two hidden witnesses. It is
  expressed as `sum_{j,k} M_e[k][i][j] · s2_iso[j] · h_iso[k]` for block `i`,
  where `M_e[k]` are the fixed ±1 structure matrices.
- (2) is an ℓ₂-norm proof (the Falcon short-vector guarantee).
- (3) is an ∞-norm proof.

If all three hold, a valid short Falcon signature under the committed key `h`
must exist — which is exactly device binding.

### How it maps onto lazer's commitment (ABDLOP + lnp-tbox)

The witness is split the way lazer's toolbox expects:

- **Ajtai / bounded part `s1` (the norm-checked witness):** the signature —
  `[s1_iso (8 blocks), s2_iso (8 blocks)]`, 16 blocks. Bounded by β via (2).
- **BDLOP / committed message part `m`:** `[h_iso (8 blocks), k (8 blocks)]`,
  16 blocks. `h` is the hidden key (this is the "credential commits `h`" piece);
  `k` is the quotient, bounded by (3).
- **Masking randomness `s2`:** internal to the commitment, sampled fresh.

The prover commits to all of this (`abdlop_commit` → commitment `tA1, tB`),
then runs `lnp_tbox_prove`, which bundles the quadratic equation (1) and the two
norm proofs (2),(3) into a single non-interactive proof `π` (Fiat–Shamir).

---

## 5. The message flow

```
                 issuance (once, out of band)
   Issuer  ───────────────────────────────────────▶  Credential = commitment binding h
                                                        (held by User)

                 verification session
   Verifier ──(1) challenge c (a fresh nonce → point in RF)──▶  User

   User     ──(2) forward c ─────────────────────────────────▶  SE
   SE       ──(3) short (s1,s2) with s1 + s2·h = c ───────────▶  User
                 (SE uses sk; sk never leaves the SE)

   User: (4) compute k = (s1 + M_h·s2 − c)/p over Rq
         (5) assemble witness [s1,s2 | h,k], commit, run lnp_tbox_prove → π

   User     ──(6) π + commitment (tA1,tB), public c ──────────▶  Verifier
   Verifier: (7) lnp_tbox_verify(π, c, commitment)  →  accept / reject
```

What crosses the wire, and what stays put:

- **Verifier → User:** `c` (public nonce).
- **User ↔ SE:** `c` in, `(s1,s2)` out — *local to the device*, never on the
  network.
- **User → Verifier:** the proof `π` (~30 KiB), the commitment, and `c`.
  **`h`, `s1`, `s2`, `k` never leave the user.**
- **`sk`** never leaves the SE at all.

Freshness: because `c` is a per-session nonce (in production, a hash-to-point of
the verifier's random challenge), a proof cannot be replayed for a different `c`
— a captured `π` is useless next session.

---

## 6. What is implemented vs. conceptual

**Implemented and passing** (`tests/fdb-test.c`, over real Falcon-512):

- real `falcon_keygen` / `falcon_decode_pubkey` for `h`,
- real `falcon_preimage_sample` for `(s1,s2)` on a random challenge `c`,
- the 8-block isoring rep and the `M_h` / `M_e[k]` structure,
- the full statement (1)+(2)+(3) through `abdlop_commit` + `lnp_tbox_prove` /
  `lnp_tbox_verify`,
- honest proof verifies; a tampered challenge is rejected; stable across many
  fresh keys.

**Modeled, not yet wired to a real credential:** in the test, "the credential
commits `h`" is represented by `h` sitting in the BDLOP-committed part of the
proof. Binding that committed `h` to an actual anoncred credential (so the
verifier is convinced it's the *issued* key, tied to the rest of the attributes)
is the integration step — it slots into the pq-gabi / anoncred backend, not a
change to this proof.

**Also stand-ins:** the challenge `c` is drawn uniformly here rather than via
Falcon's HashToPoint, and the norm bounds `β`, `B'` and the `q`-no-wrap margin
were carried over from anoncred — all fine for a functional PoC but they want a
cryptographer's sign-off before production.

---

## 7. Cost (measured)

Apple Silicon arm64, `-O2`, HEXL on its portable (non-AVX) path:

- **proof size ≈ 30.1 KiB**,
- **prove ≈ 0.18–0.40 s** (rejection-sampling variance),
- **verify ≈ 0.145 s**.

See `falcon-devicebind-design.md` §7 for details.
