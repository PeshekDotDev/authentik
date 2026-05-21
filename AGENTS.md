# AGENTS.md

## Cursor Cloud specific instructions

### Architecture Overview

authentik is an open-source Identity Provider (IdP) with a polyglot architecture:

| Layer | Language | Key Detail |
|-------|----------|------------|
| Core backend | Python 3.14 (Django) | `uv run` for all Python commands |
| HTTP frontend / proxy | Go 1.26 | `go run ./cmd/server` or via `ak server` |
| Process orchestrator | Rust | `cargo run -- allinone` runs server + worker |
| Web UI | TypeScript (Lit) | Built with esbuild; `corepack npm run build --prefix web` |

PostgreSQL is the **only** external dependency — it handles data, caching, channels, and task queuing (no Redis).

### Starting Services

1. **PostgreSQL**: `sudo docker compose -f scripts/compose.yml up -d postgresql`
2. **Generate dev config** (if `local.env.yml` doesn't exist): `make gen-dev-config`
3. **Run migrations**: `uv run python -m lifecycle.migrate`
4. **Build web UI**: `corepack npm run build --prefix web`
5. **Start server**: `make run` (runs `uv run ak allinone`, which starts both server and worker)

The server listens on `http://localhost:9000` (HTTP) and `https://localhost:9443` (HTTPS).

### Important Gotchas

- **Node.js 24+ required**: The `.npmrc` has `engine-strict=true`. Use `nvm install 24 && nvm use 24`.
- **Python 3.14 required**: `pyproject.toml` specifies `requires-python = "==3.14.*"`. Install via `deadsnakes` PPA on Ubuntu.
- **Rust/PyO3 linking**: When building the Rust binary, set `export PYO3_PYTHON=/workspace/.venv/bin/python3.14` so PyO3 links against the correct Python version (not the system python3.12).
- **npm ignore-scripts**: The root `.npmrc` blocks install scripts by default. After `npm ci --prefix web`, run `make web-postinstall` to rebuild native bindings (esbuild, etc.).
- **Corepack**: The project uses corepack for npm version management. Run `node scripts/node/setup-corepack.mjs` before `npm ci` if corepack isn't set up.
- **Docker in Cloud Agent VM**: Requires `fuse-overlayfs` storage driver and `iptables-legacy`. See the Docker setup in the system prompt.

### Running Tests

- **Python**: `uv run python manage.py test --keepdb <test_file_path>` (e.g. `authentik/core/tests/test_models.py`)
- **Go**: `go test -v ./internal/...` (some tests in `internal/outpost/proxyv2` need a configured PostgreSQL connection)
- **Rust**: `cargo test --workspace` (requires `PYO3_PYTHON` set correctly; some config/db tests need runtime env)
- **Web**: `corepack npm run test --prefix web`

### Linting

- **Python**: `uv run ruff check authentik` and `uv run black --check authentik`
- **Web**: `corepack npm run lint --prefix web`
- **Go**: `golangci-lint run -v`
- **Rust**: `cargo clippy --workspace`
- **Spellcheck**: `npm run lint:spellcheck` (root)

### Default Admin User

The default admin user created by blueprints is `akadmin`. In development, reset its password via:
```python
uv run python -c "
import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'authentik.root.settings')
django.setup()
from authentik.core.models import User
u = User.objects.get(username='akadmin')
u.set_password('your-password')
u.save()
"
```
