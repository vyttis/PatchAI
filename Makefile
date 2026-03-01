.PHONY: help dev-api dev-worker dev-beat dev-frontend test-backend test-frontend lint migrate

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# --- Development ---

dev-api: ## Run FastAPI dev server
	cd backend && uvicorn backend.app.main:app_with_middleware --reload --host 0.0.0.0 --port 8000

dev-worker: ## Run Celery worker
	cd backend && celery -A backend.app.workers worker --loglevel=info

dev-beat: ## Run Celery Beat scheduler
	cd backend && celery -A backend.app.workers beat --loglevel=info

dev-frontend: ## Run Next.js dev server
	cd frontend && npm run dev

# --- Testing ---

test-backend: ## Run backend tests
	cd backend && pytest -v

test-frontend: ## Run frontend tests
	cd frontend && npm run lint && npm run build

lint: ## Lint all code
	cd backend && ruff check .
	cd frontend && npm run lint

# --- Database ---

migrate: ## Run Alembic migrations
	cd backend && alembic upgrade head

migrate-new: ## Create new migration (usage: make migrate-new msg="description")
	cd backend && alembic revision --autogenerate -m "$(msg)"

# --- Deploy ---

deploy-api: ## Deploy API to Fly.io Frankfurt
	cd backend && flyctl deploy --config fly.api.toml --remote-only

deploy-worker: ## Deploy Worker to Fly.io Frankfurt
	cd backend && flyctl deploy --config fly.worker.toml --remote-only

deploy-beat: ## Deploy Beat to Fly.io Frankfurt (1 instance only)
	cd backend && flyctl deploy --config fly.beat.toml --remote-only
