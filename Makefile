PYTHON ?= python3

.PHONY: check validate validate-pack test stats pack

## Run the complete catalog gate used by CI and release verification.
check: validate validate-pack test stats

validate:
	$(PYTHON) tools/validate.py

validate-pack:
	$(PYTHON) tools/validate_pack.py

test:
	$(PYTHON) -m unittest discover -s tests

stats:
	$(PYTHON) tools/stats.py

pack:
	$(PYTHON) tools/build_pack.py --output atropos-core-$$(cat VERSION).zip
