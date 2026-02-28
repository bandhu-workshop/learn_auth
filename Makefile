# Postgres (Docker Compose)
pgup:
	@docker compose up -d

pgdown:
	@docker compose down

# Format and type checking
check_format:
	@echo "Checking format..."
	uv run ruff check && uv tool run ruff format --check

check_type:
	@echo "Checking types..."
	uv run mypy --package learn_auth

format:
	@echo "Formatting code..."
	uv tool run ruff check --fix && uv tool run ruff format

# API server
run:
	@echo "Starting API server..."
	uv run python -m uvicorn src.learn_auth.main:app --host 0.0.0.0 --port=8080 --reload