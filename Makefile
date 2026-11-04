# Small helper commands. Run `make help` to list them.
# Everything uses the virtualenv in .venv (create it with `make venv`).

PY := .venv/bin/python

.PHONY: help venv test demo fuzz lint fmt serve fixtures vendor bundle

help:
	@echo "make venv      create .venv and install ctfc + dev tools"
	@echo "make test      run the test suite"
	@echo "make demo      run every command of docs/HANDOFF.md section 7 and check it"
	@echo "make fuzz      throw broken files at every format reader (long sweep)"
	@echo "make lint      check the code with ruff"
	@echo "make fmt       auto-format the code with ruff"
	@echo "make fixtures  regenerate tests/fixtures/"
	@echo "make serve     start the web UI on http://127.0.0.1:8137"
	@echo "make vendor    download the embedded CyberChef (needs internet, once)"
	@echo "make bundle    dist/ctfc-bundle/: installs on a machine without internet"

venv:
	python3 -m venv .venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

# The demo list of the handoff, executed: each command must exit as expected and
# print what it is supposed to print (usually the flag). ARGS=-v shows the output.
demo:
	$(PY) tests/demo.py $(ARGS)

# A short fixed-seed sweep already runs inside `make test`; this is the long one.
# SEED=7 make fuzz runs a different one.
SEED ?= 1
ROUNDS ?= 800

fuzz:
	$(PY) tests/fuzz_formats.py --rounds $(ROUNDS) --seed $(SEED)

lint:
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

fmt:
	$(PY) -m ruff check --fix .
	$(PY) -m ruff format .

fixtures:
	$(PY) tests/make_fixtures.py

serve:
	$(PY) -m ctfc serve

vendor:
	scripts/fetch_vendor.sh

bundle:
	scripts/make_bundle.sh
