# Contributing to kinz-secure-commerce-hub

## Development setup

```bash
git clone https://github.com/Kinz-org/kinz-secure-commerce-hub.git
cd kinz-secure-commerce-hub

# Backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r src/api/requirements.txt

# Frontend
cd src/frontend && npm install
```

## Running tests

```bash
# Backend (67 tests, ~5s)
pytest tests/ -v

# Frontend
cd src/frontend && npx jest

# Lint
cd src/api && ruff check .

# Full stack via Docker
docker compose up --build -d
```

## CI

CI runs on push + pull_request to main:
- Backend tests (pytest with coverage) + Codecov upload
- Frontend tests (Jest with coverage)
- Security scans (Trivy, gitleaks)

## Pull request workflow

1. Create a branch from `main`.
2. Make your changes. Keep diffs small.
3. Run `pytest tests/ -v` and `cd src/api && ruff check .` locally.
4. Open a PR with a clear description.
5. Squash-merge when CI is green.
