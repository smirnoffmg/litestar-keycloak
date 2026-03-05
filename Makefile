# Run all checks and unit tests (use after each step / before commit)
.PHONY: check test test-unit test-integration test-examples

check:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy src/
	uv run pytest -m "not integration"

# Test targets (unit = default addopts exclude integration; integration = Keycloak container)
test-unit:
	uv run pytest

test-integration:
	uv run pytest -m integration -v --timeout=120

test: test-unit test-integration

# Examples smoke test: run ./examples/test.sh (Keycloak and example app must be running)
test-examples:
	./examples/test.sh
