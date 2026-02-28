# RootScope

A clean Taproot script-path analyzer with:
- Python backend for deterministic cryptographic analysis
- React frontend for interactive visualization

RootScope is part of the same open Bitcoin education/tooling ecosystem as
[`mastering-taproot`](https://github.com/aaron-recompile/mastering-taproot)
and [`btcaaron`](https://github.com/aaron-recompile/btcaaron).

## Product Preview

RootScope UI screenshots:

![RootScope - Merkle Tree](docs/images/rootscope-merkle-tree.png)
![RootScope - Hash Steps](docs/images/rootscope-hash-steps.png)
![RootScope - Key Derivation](docs/images/rootscope-key-derivation.png)

Optional demo GIF:

```md
![RootScope Demo](docs/images/rootscope-demo.gif)
```

## Public Repository Structure

- `RootScope.jsx` — React UI (input, tabs, rendering)
- `backend/app.py` — FastAPI server (`/health`, `/analyze`)
- `backend/fetch_witness.py` — `txid + vin` witness resolver (`/fetch-witness`)
- `backend/analyzer.py` — Control block parsing + Taproot analysis pipeline
- `backend/crypto.py` — TaggedHash, Merkle, secp256k1 arithmetic, bech32m
- `backend/models.py` — API contract models
- `backend/tests/` — backend tests
- `frontend/` — Vite React app shell for local preview
- `Makefile` / `scripts/test_all.sh` — one-command regression helpers

## API Contract

`POST /analyze`

Request:

```json
{
  "controlBlock": "hex",
  "script": "hex",
  "network": "testnet",
  "expectedAddress": "tb1p... (optional)"
}
```

Response fields (stable contract):

- `cb` (parsed control block)
- `steps` (TapLeaf + TapBranch walkthrough)
- `leafHex`, `merkleRootHex`, `tweakHex`
- `outputKey`, `computedParity`, `parityMatch`
- `address`
- `checks.expectedAddressMatch` and reason

`GET /fetch-witness?txid=<txid>&vin=<index>&network=auto|testnet|mainnet`

- Auto-resolves witness input into `scriptHex` + `controlBlockHex`
- Returns `witnessStack` and detected `network/source`
- Intended to prefill UI before calling `/analyze`

## Local Run

### 1) Create virtual environment and install dependencies

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -r backend/requirements.txt
```

### 2) Run tests

```bash
./.venv/bin/python -m unittest discover -s backend/tests -p "test_*.py"
```

### 2.1) Run chapter06/07/08 regression in one command

```bash
./.venv/bin/python backend/scripts/run_regression.py
```

Expected output ends with:

```text
SUMMARY: 3/3 PASS
```

### 2.2) Shortcut commands

From project root:

```bash
make regression
```

Run all backend checks (unit tests + chapter06/07/08 regression):

```bash
./scripts/test_all.sh
```

### 3) Start backend

```bash
./.venv/bin/python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload
```

### 4) Frontend integration

`RootScope.jsx` sends analysis requests to:

- default: `http://127.0.0.1:8000`
- override: set `window.__ROOTSCOPE_API_BASE__ = "http://your-host:port"` before mounting the component

## Verified Vectors

Tests include vectors based on `mastering-taproot`:

- Chapter 06: single-leaf control block verification
- Chapter 07: dual-leaf control block verification
- Chapter 08: four-leaf control block verification

## Acknowledgements

This project is supported by [OpenSats](https://opensats.org/).

## License

- Code: **MIT** (see `LICENSE.md`)
- Documentation/content: **CC-BY-SA 4.0** (see `LICENSE.md`)
