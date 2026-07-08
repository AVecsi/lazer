# Falcon device-binding proof — design

**Goal.** A device has a Secure Element (SE) that holds a Falcon-512 secret key
and will only *sign* messages; it exposes the public key `h`. A credential
stores a commitment to `h`. We want a zero-knowledge proof that:

1. the SE just produced a **valid Falcon signature on a fresh challenge** given
   by the verifier, and
2. the key that verifies it is **exactly the one committed in the credential**,

**without revealing `h` or the signature.** (Hiding `h` is what gives
unlinkability — otherwise every showing is trivially linkable by `h`.)

The two requirements collapse into one statement over a single hidden witness
`h`, proven with lazer's quadratic + norm machinery (`lnp-tbox`).

---

## 1. The Falcon relation (what "valid" means)

Falcon-512 over `RF = Z_q[X]/(X^512 + 1)`, `q = 12289`. A signature on message
`m` is `(nonce, s2)` (with `s2` short); verification:

```
c  = HashToPoint(nonce ‖ m)          ∈ RF        (public: depends only on nonce, m)
s1 = c − s2·h   (mod X^512+1, mod q)             (recomputed)
accept  iff  ‖(s1, s2)‖² ≤ ⌊β²⌋,     β² = 34034726
```

Two facts make this provable and keep `c` public:

- **`c` does not depend on `h`.** `HashToPoint` hashes `nonce ‖ m` only. The
  verifier picks `m = challenge`, the SE returns `nonce`, so `c` is a public
  constant in the proof — no hash has to be proven in ZK.
- **`q = 12289` is exactly lazer's statement-ring modulus** and deg-512 objects
  are the same 8-block structure over `Rp = Z_q[X]/(X^64+1)` that `anoncred.c`
  already uses (`poly_toisoring` / `lin_toisoring`).

The only nonlinearity is the product `s2·h`. In `anoncred.c` the signing key was
the **issuer's public** key, encoded as a public matrix `B2` → "multiply by `h`"
was **linear**. Here `h` is **secret**, so `s2·h` is a product of two witnesses
→ **quadratic**. That is the whole reason this needs `lnp-tbox`/`lnp-quad-eval`
rather than the linear `lin-proofs` wrapper.

---

## 2. Ring representation and the bilinear product

Represent each deg-512 element as 8 blocks over `Rp` via the isoring map
(`x = (x_0, …, x_7)`, `x_i ∈ Rp`), exactly as `anoncred.c` does. Ring
multiplication `s2·h` becomes a fixed **bilinear map** `B: Rp^8 × Rp^8 → Rp^8`:

```
(s2·h)_i = Σ_{j,k}  γ_{ijk} · s2_j · h_k          for i = 0..7,   γ_{ijk} ∈ Rp
```

The **structure constants** `γ_{ijk}` encode the negacyclic digit/carry
structure of `X^512+1` in the block basis. We do **not** hand-derive them: lazer
already computes "multiply by a deg-512 element" as an 8×8 `Rp` matrix via
`lin_toisoring` (this is how `anon_decode_pk` builds `B2`). Since that matrix is
`Rp`-linear in the input's blocks,

```
γ_{ijk} = ( lin_toisoring(e_k) )[i][j]
```

where `e_k` is the k-th block-basis element. So 8 calls to `lin_toisoring` on
basis elements yield all `γ_{ijk}` mechanically, offline. (`γ_{ijk}` are small
fixed `Rp` polys — monomials/±shifts.)

---

## 3. The zero-knowledge statement

Witness `w` (all over `Rp`), partitioned by how `lnp-tbox` commits it:

| part | symbol | dim | committed in | norm |
|---|---|---|---|---|
| commitment randomness | `r` | 16 | Ajtai (`s1`) | `‖r‖₂ ≤ 109` |
| signature | `s2` | 8 | Ajtai (`s1`) | see below |
| derived low part | `s1sig` | 8 | Ajtai (`s1`) | `‖(s1sig,s2)‖₂ ≤ β` |
| **SE public key** | `h` | 8 | **BDLOP (`m`)** | none (uniform) |

`h` is uniform mod q, so it cannot carry a small-norm bound → it must sit in the
**BDLOP (message) part** of ABDLOP, not the Ajtai part. This is standard
`lnp-tbox` usage (see `tests/lnp-tbox-test.c`) — and it is *not* the broken path:
the `l>0` bug we hit earlier was specifically the `lin-proofs` wrapper's
`m_indices` scatter, which we bypass by writing the statement directly at the
`lnp-tbox` level. **(Validate this first — see Risks.)**

**Constraints.**

(a) *Verification / definition of `s1sig`* — 8 quadratic `Rp` equations, `i=0..7`:

```
s1sig_i + Σ_{j,k} γ_{ijk} · h_k · s2_j − c_i = 0
```

As an `lnp-quad-eval` form `sᵀ R2 s + r1ᵀ s + r0 = 0` per `i`:
- `R2` (upper-diagonal, sparse): entry `γ_{ijk}` coupling witness slots
  `h_k` and `s2_j`  → the only quadratic terms.
- `r1`: coefficient `1` on slot `s1sig_i` (the sole linear term).
- `r0`: `−c_i` (public constant, the challenge point block).

(b) *Norm bound* — exact-ℓ₂ on `(s1sig, s2) ∈ Rp^16`: `‖(s1sig,s2)‖₂ ≤ β`,
`β = ⌊√34034726⌋`. (Same bound `anoncred.c` already uses for Falcon `s1,s2`.)

(c) *Credential binding* — the credential stores a commitment
`t_h = AR·r + AM·h` (public `t_h`, fixed at issuance; `AR` 8×16, `AM` 8×8 the
fixed public matrices). 8 **linear** `Rp` equations (a degenerate quad-eval with
`R2 = 0`) prove the same `(r, h)` open `t_h`. This ties the ephemeral proof to
the persistent credential without revealing `h`.

Nothing else is revealed: `h`, `s2`, `s1sig`, `r` are all hidden; the verifier
sees only `t_h`, `c` (from `nonce, challenge`), and the proof.

Totals: witness ≈ **40** `Rp` elements; **8 quadratic + 8 linear** equations;
**one** ℓ₂ norm proof on 16 elements (plus the `r` bound). Comparable in size to
`anoncred`'s P2 statement (witness 48–56).

---

## 4. Mapping to lazer

- **Layer:** `lnp-tbox` **directly** (not `lin-proofs`), template
  `tests/lnp-tbox-test.c`: build `spolymat R2` / `spolyvec r1` / `poly r0` per
  equation (the `_scatter_smat`/`_scatter_vec` pattern), `abdlop_commit`,
  `lnp_tbox_prove`, `lnp_tbox_verify`. Falcon bits reused from `anoncred.c`
  (`falcon_keygen`, `falcon_preimage_sample` = the SE signing step,
  `poly_toisoring`, `lin_toisoring`, hash-to-point for `c`).
- **New C file** (e.g. `src/devicebind.c` + a `demos/devicebind/` driver),
  structured like `anoncred.c`.
- **Parameters:** a new `lnp-tbox` spec (`scripts/lnp-tbox-codegen.sage`):
  `deg=64`, `mod=12289`, witness partition `[r(16) | s2,s1sig(16) | h(8)]`,
  `wl2 = [109, β, —]`, the 8 quadratic + 8 linear equations declared, `h` in the
  BDLOP part. Regenerate → re-runs the lattice estimator for security.

---

## 5. Protocol flow

```
Issuance (once):  SE.keygen → h ;  credential commits  t_h = AR·r + AM·h  (r secret, kept by client)
Show:
  Verifier → challenge  (random m)
  Client  → SE.sign(m)  ⇒ (nonce, s2) ;  s1sig = c − s2·h ;  c = HashToPoint(nonce‖m)
  Client  : lnp_tbox_prove over w=(r,s2,s1sig,h) for constraints (a),(b),(c)
  Client  → (nonce, proof)
  Verifier: compute c ;  lnp_tbox_verify against (t_h, c)  ⇒ accept/reject
```

Accept ⟹ "the holder possesses the SE key committed in `t_h`, and that key just
signed my fresh challenge" — with `h` and the signature hidden.

---

## 6. Risks / open points

1. **BDLOP witness in a quadratic term — ✅ VALIDATED.** `tests/devicebind-micro-test.c`
   proves `a·b = d` with `a` the small Ajtai witness (`s1_0`, like the Falcon
   signature `s2`) and `b` the **unbounded BDLOP witness** (`m_0`, like the
   hidden key `h`), `d` public — one real product term `R2[a][b]=1` at the raw
   `lnp-quad` level. Honest proof verifies; tampered `d` rejected; exit 0. This
   is the core mechanism of `s2·h`, and confirms the BDLOP path works directly
   (unaffected by the `lin-proofs` `m_indices` bug). *(Gotcha found: the ABDLOP
   commitment randomness `s2` must be initialized small ±1 — an uninitialized
   `s2` self-verifies but wedges the prover on the next call.)*
2. **`s2·h` isoring multiplication — ✅ VALIDATED.** `tests/devicebind-isoring-test.c`
   confirms `M_h = lin_toisoring(h)` faithfully represents "multiply by the
   hidden deg-512 `h`" as an 8×8 `Rp` block matrix: `M_h · toisoring(s2)` equals
   `toisoring(h·s2)` computed independently by schoolbook negacyclic convolution
   mod 12289 → MATCH. So the quadratic form's structure constants are exactly
   the entries of `M_h` (equivalently `γ_{ijk} = lin_toisoring(e_k)[i][j]`), and
   lazer also offers `quad_toisoring` to push a whole quadratic form through the
   isoring. The multiplication is no longer a risk.

3. **The remaining crux — proving a mod-`p`=12289 *quadratic* relation.** The
   Falcon relation holds mod 12289, but the raw `lnp-quad`/`lnp-tbox` prover
   proves over its big proof modulus `q` (the micro-test's `a·b=d` held over the
   proof ring). lazer's mod-`p` machinery (`p`/`pinv`/`dprime` scaling +
   `toisoring`) lives in the **linear** `lin-proofs.c` wrapper; there is no
   ready quadratic analog. Two routes, both real work:
   - (a) a quadratic analog of the `lin-proofs` mod-`p`/isoring bridge, or
   - (b) explicit quotient witnesses `k_i` with `s1_i + (s2·h)_i − c_i − 12289·k_i = 0`
     over `q`, with a range bound on the `k_i` (needed for soundness).
   Plus a bespoke parameter set (quadratic + norm + mod-`p`), which no existing
   codegen emits directly. **This is the substantive, still-unbuilt part.**
3. **Unlinkability across multiple showings.** A fixed public `t_h` is linkable
   across shows. The minimal PoC does one show; for many, re-randomize `t_h`
   (ABDLOP is hiding) or prove opening of a re-randomized commitment. Out of
   scope for the PoC, supported by the primitive.
4. **Trust anchor.** As in the current pq-irmago flow, "the credential commits
   `h`" presumes an issuer vouched for `h` at issuance; that issuance/attestation
   step is orthogonal to this proof.

---

## 7. Size & performance (measured)

Measured from `tests/fdb-test.c` (`q≈2⁵¹`, d=64, m1=16, l=16, NEQ=8),
Apple Silicon arm64, `-O2`, HEXL on its portable (non-AVX) path:

| metric      | value                                             |
|-------------|---------------------------------------------------|
| proof size  | **~30.1 KiB** (30 788–30 825 B across runs)       |
| prove       | **~0.18–0.40 s** (mean ≈0.26 s; commit + `lnp_tbox_prove`, rejection-sampling variance) |
| verify      | **~0.145 s** (stable)                             |

Proof size varies by a few bytes per signature (the Gaussian-encoded `z*` /
hint elements). An x86 AVX-512 HEXL build should be materially faster on the
NTT-bound prove/verify; these arm64 numbers are a conservative floor. The
quadratic `s2·h` (8 equations, dense in the `h×s2` block coupling) is the main
cost over the linear `anoncred` disclosure proof.

---

## 8. Build status (2026-07)

Every structural unknown is now resolved:

- **Quadratic product with a hidden BDLOP witness** — validated
  (`tests/devicebind-micro-test.c`, passes).
- **`s2·h` isoring multiplication (`M_h`)** — validated
  (`tests/devicebind-isoring-test.c`, MATCH).
- **mod-`p` mechanism** — understood: lazer derives the quotient via `pinv`
  scaling for *linear* relations; the quadratic case needs the explicit,
  norm-bounded quotient `k` (route b).
- **Parameters** — a toy core-relation `lnp-tbox` spec generates a secure,
  complete set: `tests/devbind-params.sage` → `tests/devbind-params.h`
  (`q≈2⁴⁰`, m1=10, l=2, one ℓ₂ proof on `(s2,s1)`, one ∞ proof on `k`).
  Key gotcha: the completeness gate is a *dimension* condition
  `(m1+Z)·d ≥ 5·KAPPA` (codegen line 330), so `m1` must be padded to ~10 —
  nothing to do with the norm bounds.

**PoC built and passing** — `tests/devbind-test.c` drives `lnp_tbox_prove`/
`verify` for the toy relation: `R2` = the `s2·h` term, `r1` = `s1` (coeff 1) &
`k` (coeff `−p`), `r0` = `−c`; ℓ₂ proof (`Es` selector) on `(s2,s1)`; ∞ proof
(`Dm` selector) on `k`; `h`,`k` in the BDLOP part; empty binary/`Ds`. Honest
proof verifies; a tampered public challenge `c` (i.e. `r0`) is rejected; exit 0,
stable across runs. Bounds and the quotient wiring still merit a cryptographer's
review before any real use (soundness of `Bprime`, the `q`-no-wrap margin).

Gotchas found while building (both fixed):
- do **not** `set_empty` a freshly-allocated scatter *target*;
- never `poly_alloc` through an uninitialized `poly_ptr` array slot — it writes
  through garbage and silently corrupts the heap (this manifested as a bogus
  read-only pointer three functions away).

**Full Falcon-512 — built and passing** — `tests/fdb-test.c` +
`tests/fdb-params.{sage,h}` (`q≈2⁵¹`, d=64, m1=16, l=16, one ℓ₂ proof on the
16-block `(s1,s2)`, one ∞ proof on the 8-block quotient `k`). It uses a real
Falcon key (`falcon_keygen`/`falcon_decode_pubkey`), a real preimage
(`falcon_preimage_sample`), the 8-block isoring rep, and the `M_h`/`M_e[k]`
structure. Honest proof verifies; a tampered challenge is rejected; exit 0,
stable across many fresh keys. Measured on the dev machine: `max|gamma| = 1`
(confirming the block-negacyclic iso — the structure constants γ are ±1, so the
`s2·h` product does **not** blow up past `q`); `‖(s1,s2)‖² ≈ 2.9·10⁷ ≤ β² =
34034726`; `|k|_∞ ≈ 3·10³ ≪ B' = 8958759`.

Two representation bugs found and fixed while scaling up the toy to Falcon-512:

1. **Cross-ring `poly_set` copies garbage.** `s1iso`/`s2iso`/`h`/`γ` are built
   over `RP` (`q=12289`); the witness and `R2`/`r1` live over `Rq` (`q≈2⁵¹`).
   The two rings have incompatible CRT/limb layouts, so `poly_set` between them
   copies the raw representation, not the coefficient values — this produced a
   bogus `‖(s1,s2)‖² ≈ 2¹⁰⁷`, driving the ℓ₂ slack negative and rejection-looping
   the prover forever. **Fix:** transfer *coefficient values* across rings
   (`fromcrt`+`redc` the source, then `get`/`set_coeffvec_i64` — the `cpq`
   helper), never `poly_set`.
2. **The quotient must be computed over `Rq`, not `RP`.** `s1+s2·h−c` reduces to
   `0` over `RP` (that *is* the Falcon relation mod `p`), so a quotient derived
   there is identically zero. **Fix:** compute `M_h·s2iso` over `Rq` (integer
   arithmetic — safe because `s2` is the *short* signature, so the product stays
   ~2³¹ ≪ q), then `k = (s1iso + M_h·s2iso − ciso)/p` divides exactly.

Bounds and the quotient wiring still merit a cryptographer's review before any
real use (soundness of `B'`, the `q`-no-wrap margin, and the ℓ₂ slack, which is
tight — β² is Falcon's exact norm ceiling).
