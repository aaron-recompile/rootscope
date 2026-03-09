# Data Directory

This directory is for reproducible sample inputs used by RootScope examples.

Included:

- `sample_batch.csv`: tiny self-contained sample for `backend.cli batch`
- `empirical_sample_v0_1_0.csv`: public empirical sample (300 rows) extracted from a larger local scan dataset

CSV schema used by empirical samples:

- `txid`: spending transaction id
- `vin`: input index in spending transaction
- `network`: `mainnet` or `testnet`
- `scriptHex`: revealed tapscript hex
- `controlBlockHex`: control block hex
- `expected`: expected Taproot address from source dataset
- `blockHeight`: observed block height in source dataset
- `source`: sample tag/version

Note:

- empirical samples are reproducibility artifacts and may be distribution-biased
