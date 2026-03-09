# Reproduce and CLI Reference

This page contains detailed commands that were moved out of the top-level `README.md`.

## Backend Validation

Run unit tests:

```bash
./.venv/bin/python -m unittest discover -s backend/tests -p "test_*.py"
```

Run chapter06/07/08 vectors:

```bash
./.venv/bin/python backend/scripts/run_regression.py
```

Run official BIP341 script-path vectors:

```bash
./.venv/bin/python backend/scripts/run_bip341_vectors.py
```

Shortcuts:

```bash
make regression
make bip341-vectors
./scripts/test_all.sh
```

## API Endpoints

- `POST /analyze`
- `GET /fetch-witness?txid=<txid>&vin=<index>&network=auto|testnet|mainnet`

## CLI: Single Transaction

```bash
./.venv/bin/python -m backend.cli tx <txid> --vin <n> --network mainnet
./.venv/bin/python -m backend.cli tx <txid> --vin <n> --network testnet --json
```

## CLI: Batch

From repo sample CSV:

```bash
./.venv/bin/python -m backend.cli batch \
  --input-csv data/sample_batch.csv \
  --out outputs/sample_batch.jsonl \
  --summary outputs/sample_batch_summary.csv
```

## Batch Report Rendering

```bash
./.venv/bin/python backend/scripts/render_batch_report.py \
  --summary outputs/sample_batch_summary.csv \
  --jsonl outputs/sample_batch.jsonl \
  --out outputs/sample_batch_report.md \
  --name sample-batch
```

Shortcut:

```bash
make batch-report
```
