# btcdeb Cross-Check (Reproducible Example)

This page shows a minimal side-by-side check between:

- script execution behavior in [`btcdeb`](https://github.com/bitcoin-core/btcdeb)
- Taproot reconstruction output in RootScope (`control block -> merkle root -> tweak -> address`)

## Scope

`btcdeb` and RootScope validate different layers:

- `btcdeb`: script execution semantics (stack evolution, op-by-op behavior)
- RootScope: Taproot commitment reconstruction (BIP341 path and address)

They are complementary, not duplicates.

## Example Input (Chapter07-style script-path witness)

Source and attribution:

- from **Mastering Taproot** by Aaron Zhang:
  - Book page: [Mastering Taproot (Leanpub)](https://leanpub.com/mastering-taproot)
  - Companion repository: [aaron-recompile/mastering-taproot](https://github.com/aaron-recompile/mastering-taproot)
- this RootScope example follows the same Chapter07 dual-leaf construction flow and witness style

- witness preimage: `68656c6c6f776f726c64` (`helloworld`)
- script:
  `a820936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af8851`
- control block:
  `c050be5fc44ec580c387bf45df275aaa8b27e2d7716af31f10eeed357d126bb4d32faaa677cb6ad6a74bf7025e4cd03d2a82c7fb8e3c277916d7751078105cf9df`
- expected address:
  `tb1p93c4wxsr87p88jau7vru83zpk6xl0shf5ynmutd9x0gxwau3tngq9a4w3z`

## 1) RootScope reconstruction

```bash
./.venv/bin/python -m backend.cli tx b61857a05852482c9d5ffbb8159fc2ba1efa3dd16fe4595f121fc35878a2e430 --vin 0 --network testnet
```

Expected highlights:

- `merkle root = 868ba8150cd670ce73709de6d9056427e2974c4214a729c6b690647947441219`
- `address = tb1p93c4wxsr87p88jau7vru83zpk6xl0shf5ynmutd9x0gxwau3tngq9a4w3z`
- `parity match = True`

## 2) btcdeb script-step check

Install [`btcdeb`](https://github.com/bitcoin-core/btcdeb) first (outside this repo), then run:

```bash
btcdeb '[OP_SHA256 936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af OP_EQUALVERIFY OP_1]' 68656c6c6f776f726c64
```

Interactive checks:

- use `step` repeatedly to execute each opcode
- ensure `OP_SHA256` result equals target hash
- ensure `OP_EQUALVERIFY` succeeds (no script failure)

## 3) Consistency interpretation

If both checks pass:

- script execution is semantically valid under witness input (`btcdeb`)
- Taproot commitment path reconstructs the same output address (`RootScope`)

That gives a practical two-layer sanity check for script-path cases.
