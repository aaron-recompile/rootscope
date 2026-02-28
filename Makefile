PYTHON ?= ./.venv/bin/python

.PHONY: regression test-backend

regression:
	$(PYTHON) backend/scripts/run_regression.py

test-backend:
	$(PYTHON) -m unittest discover -s backend/tests -p "test_*.py"
