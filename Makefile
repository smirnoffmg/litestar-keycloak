# Test targets (unit = default addopts exclude integration; integration = Keycloak container)
.PHONY: test test-unit test-integration

test-unit:
	uv run pytest

test-integration:
	uv run pytest -m integration -v --timeout=120

test: test-unit test-integration
