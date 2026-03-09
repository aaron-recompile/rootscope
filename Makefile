PYTHON ?= ./.venv/bin/python

.PHONY: regression test-backend batch-report bip341-vectors

regression:
	$(PYTHON) backend/scripts/run_regression.py

test-backend:
	$(PYTHON) -m unittest discover -s backend/tests -p "test_*.py"

batch-report:
	$(PYTHON) backend/scripts/render_batch_report.py --summary outputs/batch_50_summary.csv --jsonl outputs/batch_50.jsonl --out outputs/batch_50_report.md --name batch-50

bip341-vectors:
	$(PYTHON) backend/scripts/run_bip341_vectors.py
