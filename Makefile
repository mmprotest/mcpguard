.PHONY: install lint typecheck test run-proxy format

install:
	pip install -e .[redis]

lint:
	ruff check .
	ruff format --check .

format:
	ruff format .
	ruff check --select I .

typecheck:
	mypy mcpguard

test:
	pytest

run-proxy:
	python -m mcpguard.proxy proxy --policy examples/policy.yaml --target ws://localhost:8765
