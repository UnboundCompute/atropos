PYTHON ?= python3

.PHONY: check validate test stats

## Run the complete catalog gate used by CI and release verification.
check: validate test

validate:
	$(PYTHON) tools/validate.py

test:
	$(PYTHON) -m unittest discover -s tests

stats:
	$(PYTHON) tools/stats.py
