# Falcon-AIR

A STARK proof system that proves modular arithmetic in the ring \$\mathbb{Z}\_q\$ with $q = 12 \cdot 1024 + 1 = 12289$, tailored to the needs of the Falcon signature scheme. Built on top of the [STWO](https://github.com/starkware-libs/stwo) framework.

> **Status:** Research prototype. This code has not been audited. Do not use in production.

---

## Highlights

* **Operations proved:** modular addition, subtraction, multiplication, plus **range checking** (values in $[0,q)$).
* **Single “Big AIR”:** all constraints are wired together into one proof over consistent traces.
* **NTT/INTT circuits:** efficient polynomial evaluation & interpolation used by Falcon-like flows.
* **Precomputed tables:** roots of unity and modular inverses for fast proving.

---

## Requirements

* **Rust nightly:** pinned via `rust-toolchain.toml` to `nightly-2025-04-06` (installs `rustfmt`, `clippy`, `rust-analyzer`).
* **Rust edition:** 2024 (see `Cargo.toml`).
* **CPU:** SIMD backend from STWO is used; x86\_64 with AVX2 is recommended. Other targets may require swapping the backend.

Install the pinned toolchain:

```bash
rustup toolchain install nightly-2025-04-06
rustup default nightly-2025-04-06
```

---

## Build & Run

```bash
# Build
cargo build --release

# Run demo binary (generates a proof)
cargo run --release
# -> writes ./proof.bin (bzip2-compressed serialization of the proof)
```

---

## Using as a Library

`falcon-air` is a library crate with a demo binary. Add it as a git dependency or include it in a workspace.

<details>
<summary>Example</summary>

```rust
use bzip2::{write::BzEncoder, Compression};
use std::io::Write;

use falcon_air::{
    big_air::prove_falcon,
    POLY_SIZE, TEST_S1, PK, MSG_POINT,
};

fn main() -> anyhow::Result<()> {
    // Each input is a length-POLY_SIZE vector in Z_q
    let proof = prove_falcon(TEST_S1, PK, MSG_POINT)?;

    // Serialize + compress to a file (demo behavior of the binary)
    let mut out = BzEncoder::new(std::fs::File::create("proof.bin")?, Compression::best());
    let bytes = bincode::serialize(&proof)?;
    out.write_all(&bytes)?;
    out.finish()?;
    Ok(())
}
```

</details>

---

## What’s Inside (Directory Overview)

```
src/
  zq/            # Arithmetic over Z_q (q=12289): add, sub, mul, range_check, inverses, Q
  polys/         # Higher-level polynomial ops: multiplication, subtraction, Euclidean norm
  ntts/          # NTT/INTT circuits and preprocessed roots of unity
    ntt/         # Butterfly + merge phases for evaluation (NTT)
    intt/        # Split + ibutterfly phases for interpolation (INTT)
    roots/       # Preprocessed and inverse roots tables
  big_air/       # “Big AIR”: claims, relations, lookups, and prove_falcon() wiring
  debug/         # Constraint/trace debugging utilities and relation tracking
  lib.rs         # Public modules, constants (bounds, POLY_LOG_SIZE, etc.), test fixtures
  main.rs        # Demo binary: generates a proof and writes proof.bin
```

---

## Design Notes

* **Arithmetic modulus vs. STARK field:** Arithmetic is in \$\mathbb{Z}\_q\$ with `q = 12289` (`zq::Q`). Traces and constraints are over STWO’s base field (`M31`) using the SIMD backend. Range checks and lookups tie the two worlds together safely.
* **Traces & constraints:** Each component emits trace columns; constraints enforce the arithmetic identities, and **lookup relations** enforce range membership and table consistency (e.g., roots, inverses).
* **Single proof:** `big_air::prove_falcon(...)` builds and commits all traces and emits one `StarkProof<Blake2sMerkleHasher>`.

---

## Configuration & Constants

* `POLY_LOG_SIZE = 10` and `POLY_SIZE = 1024` (NTT-friendly power-of-two sizes).
* `SIGNATURE_BOUNDS` and the derived `LOW_SIG_BOUND` / `HIGH_SIG_BOUND` constants encode the norm bounds used by Falcon-like signatures.
* Test vectors: `TEST_S1`, `PK`, `MSG_POINT` are included for the demo proof.

---

## Tips for Development

* Formatting & linting:

  ```bash
  cargo fmt
  cargo clippy --all-targets -- -D warnings
  ```
* Tests:

  ```bash
  cargo test
  ```

  (Component tests live under modules; extend as needed.)


---

## License

If you intend this project to be **MIT-licensed**, add a `LICENSE` file to the repo (the README previously referenced one). Update this section if you choose a different license.
