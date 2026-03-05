.PHONY: check test test-unit test-integration test-examples

check:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy src/
	uv run pytest -m "not integration"

test-unit:
	uv run pytest

test-integration:
	uv run pytest -m integration -v --timeout=120

test: test-unit test-integration

test-examples:
	./examples/test.sh
