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

From empirical sample CSV:

```bash
./.venv/bin/python -m backend.cli batch \
  --input-csv data/empirical_sample_v0_1_0.csv \
  --out outputs/empirical_sample_v0_1_0.jsonl \
  --summary outputs/empirical_sample_v0_1_0_summary.csv
```

Expected summary for `empirical_sample_v0_1_0`:

- total: `300`
- success: `300`
- failed: `0`
- expected_address_match.true: `300`
- caveat: sample appears template-concentrated and shallow-depth in this window

## Batch Report Rendering

```bash
./.venv/bin/python backend/scripts/render_batch_report.py \
  --summary outputs/empirical_sample_v0_1_0_summary.csv \
  --jsonl outputs/empirical_sample_v0_1_0.jsonl \
  --out outputs/empirical_sample_v0_1_0_report.md \
  --name empirical-sample-v0.1.0
```

Shortcut:

```bash
make batch-report
```
