# Assassinate Docker Setup

This directory contains Docker configurations for running Assassinate in two primary modes:

1. **Development** - Run tests, iterate on code with hot-reload
2. **Production** - Run Assassinate in a containerized environment

## Quick Start

### Run Tests (Development)

```bash
# Run full test suite
docker compose run --rm test

# Run quick tests (unit tests only, no database)
docker compose run --rm test-quick

# Run with custom pytest args
PYTEST_ARGS="-v -k test_specific" docker compose run --rm test
```

### Run Assassinate (Production)

```bash
# Start Assassinate with PostgreSQL
docker compose up

# Run in background
docker compose up -d

# View logs
docker compose logs -f assassinate

# Stop services
docker compose down
```

### Interactive Development

```bash
# Start development shell
docker compose run --rm dev bash

# Inside the container, you can:
pytest tests/                    # Run tests
python -m assassinate           # Run Assassinate
assassinate-setup --verify      # Check installation
```

## Architecture

### Multi-Stage Dockerfile

The `Dockerfile` uses multi-stage builds for optimization:

```
┌─────────────────────────────────────────────────┐
│  base: Ubuntu 24.04 + Python + uv               │
└─────────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────┐
│  builder: Full installation                     │
│  - System packages (gcc, clang, etc.)           │
│  - Rust toolchain (rustup)                      │
│  - Build components (ipc, bridge, daemon)       │
│  - Ruby + Bundler                               │
│  - Metasploit Framework (cloned + bundled)      │
└─────────────────────────────────────────────────┘
                     ↓
        ┌────────────┴────────────┐
        ↓                         ↓
┌──────────────────┐    ┌──────────────────┐
│  production      │    │  development     │
│  (minimal)       │    │  (with dev tools)│
│  - Runtime libs  │    │  - vim, gdb, etc │
│  - Binaries only │    │  - Test files    │
│  - User: hitman  │    │  - Hot-reload    │
└──────────────────┘    └──────────────────┘
```

### Services

#### `postgres`
- **Image**: `postgres:16-alpine`
- **Purpose**: Database for Metasploit Framework
- **Port**: 5432 (internal)
- **Data**: Persisted in `postgres_data` volume

#### `assassinate` (Production)
- **Target**: `production`
- **User**: `hitman` (non-root)
- **Purpose**: Run Assassinate in production mode
- **Port**: 8080 (configurable via `ASSASSINATE_PORT`)
- **Dependencies**: PostgreSQL (waits for healthy state)

#### `dev` (Development)
- **Target**: `development`
- **User**: `hitman`
- **Purpose**: Interactive development with hot-reload
- **Port**: 8081 (configurable via `DEV_PORT`)
- **Volumes**: Source code mounted for live editing
- **Profile**: `dev` (must specify: `--profile dev`)

#### `test` (Testing)
- **Target**: `development`
- **Purpose**: Run full test suite with MSF integration
- **Dependencies**: PostgreSQL
- **Profile**: `test` (auto-activated with `run`)
- **Volumes**: Source code mounted read-only

#### `test-quick` (Quick Testing)
- **Target**: `development`
- **Purpose**: Run unit tests only (no database)
- **Profile**: `test`
- **No Dependencies**: Runs standalone

## Configuration

### Environment Variables

Create a `.env` file in the `docker/` directory:

```env
# Database
POSTGRES_PASSWORD=your_secure_password

# Logging
LOG_LEVEL=INFO

# Workspace
WORKSPACE=default

# Ports
ASSASSINATE_PORT=8080
DEV_PORT=8081

# Testing
PYTEST_ARGS=-v --tb=short --maxfail=5

# Optional: Custom config directory
CONFIG_DIR=/path/to/your/config
```

### Available Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_PASSWORD` | `assassinate_pass` | PostgreSQL password |
| `LOG_LEVEL` | `INFO` | Assassinate log level (DEBUG, INFO, WARNING, ERROR) |
| `WORKSPACE` | `default` | Workspace name |
| `ASSASSINATE_PORT` | `8080` | Production service port |
| `DEV_PORT` | `8081` | Development service port |
| `PYTEST_ARGS` | `-v --tb=short` | Pytest command-line arguments |
| `CONFIG_DIR` | `./.config` | Custom configuration directory |

## Common Tasks

### Building Images

```bash
# Build production image
docker compose build assassinate

# Build development image
docker compose build dev

# Build all images
docker compose build

# Build with no cache (fresh build)
docker compose build --no-cache
```

### Running Tests

```bash
# Full test suite
docker compose run --rm test

# Quick tests (unit tests only)
docker compose run --rm test-quick

# Specific test file
docker compose run --rm test pytest tests/test_specific.py

# With coverage
PYTEST_ARGS="--cov=python/assassinate --cov-report=html" \
  docker compose run --rm test

# Verbose output
PYTEST_ARGS="-vv" docker compose run --rm test

# Stop on first failure
PYTEST_ARGS="-x" docker compose run --rm test
```

### Development Workflow

```bash
# Start interactive development shell
docker compose run --rm dev bash

# Run Assassinate with live code changes
docker compose --profile dev up dev

# Rebuild after dependency changes
docker compose build dev

# Check installation status
docker compose run --rm dev assassinate-setup --verify
```

### Production Deployment

```bash
# Start in background
docker compose up -d

# Check status
docker compose ps

# View logs
docker compose logs -f assassinate

# Restart service
docker compose restart assassinate

# Update and restart
docker compose build assassinate
docker compose up -d assassinate

# Stop all services
docker compose down

# Stop and remove volumes
docker compose down -v
```

### Database Management

```bash
# Connect to PostgreSQL
docker compose exec postgres psql -U assassinate -d msf_db

# Backup database
docker compose exec postgres pg_dump -U assassinate msf_db > backup.sql

# Restore database
cat backup.sql | docker compose exec -T postgres psql -U assassinate -d msf_db

# Reset database
docker compose down -v
docker compose up -d postgres
```

### Debugging

```bash
# Get a shell in running container
docker compose exec assassinate bash

# Check logs
docker compose logs assassinate
docker compose logs postgres

# Inspect a service
docker compose ps assassinate
docker inspect assassinate-app

# Check resource usage
docker stats assassinate-app

# Run health check manually
docker compose exec assassinate python3 -c "from python.assassinate import *"
```

## Volumes

### Persistent Volumes

- **`postgres_data`**: PostgreSQL database files
- **`assassinate_workspace`**: Production workspace data
- **`dev_workspace`**: Development workspace data
- **`test_workspace`**: Test workspace (ephemeral)
- **`cargo_cache`**: Rust cargo registry cache
- **`target_cache`**: Rust build artifacts cache

### Managing Volumes

```bash
# List volumes
docker volume ls | grep assassinate

# Inspect a volume
docker volume inspect assassinate-workspace

# Remove all volumes (DESTRUCTIVE)
docker compose down -v

# Backup a volume
docker run --rm -v assassinate-workspace:/data -v $(pwd):/backup \
  alpine tar czf /backup/workspace-backup.tar.gz /data

# Restore a volume
docker run --rm -v assassinate-workspace:/data -v $(pwd):/backup \
  alpine tar xzf /backup/workspace-backup.tar.gz -C /
```

## Troubleshooting

### Tests Failing

```bash
# Check if dependencies are installed
docker compose run --rm test assassinate-setup --verify

# Rebuild with no cache
docker compose build --no-cache dev

# Check database connection
docker compose exec postgres pg_isready -U assassinate

# View detailed logs
PYTEST_ARGS="-vv --log-cli-level=DEBUG" docker compose run --rm test
```

### Build Failures

```bash
# Clean everything and rebuild
docker compose down -v
docker system prune -af
docker compose build --no-cache

# Check disk space
docker system df

# View build logs
docker compose build assassinate 2>&1 | tee build.log
```

### Container Won't Start

```bash
# Check logs
docker compose logs assassinate

# Check health status
docker compose ps

# Try running interactively
docker compose run --rm assassinate bash

# Verify installation
docker compose run --rm assassinate assassinate-setup --verify
```

### Performance Issues

```bash
# Check resource usage
docker stats

# Increase resources in Docker Desktop settings
# Recommended: 4 CPU, 8GB RAM

# Use volume caching
docker compose down
docker volume rm assassinate-cargo-cache assassinate-target-cache
docker compose up --build
```

### Database Connection Issues

```bash
# Check if PostgreSQL is healthy
docker compose ps postgres

# Check connection from app
docker compose run --rm assassinate \
  psql -h postgres -U assassinate -d msf_db

# Reset database
docker compose down postgres
docker volume rm assassinate-postgres-data
docker compose up -d postgres
```

## Advanced Usage

### Custom Builds

```bash
# Build for a specific target
docker build -f docker/Dockerfile --target production -t assassinate:prod ..
docker build -f docker/Dockerfile --target development -t assassinate:dev ..

# Build with build args
docker build -f docker/Dockerfile \
  --build-arg RUST_VERSION=1.92.0 \
  -t assassinate:custom ..
```

### Using Docker Without Compose

```bash
# Create network
docker network create assassinate-network

# Run PostgreSQL
docker run -d --name assassinate-db \
  --network assassinate-network \
  -e POSTGRES_USER=assassinate \
  -e POSTGRES_PASSWORD=pass \
  -e POSTGRES_DB=msf_db \
  postgres:16-alpine

# Run Assassinate
docker run -d --name assassinate-app \
  --network assassinate-network \
  -e DATABASE_URL=postgresql://assassinate:pass@assassinate-db:5432/msf_db \
  -p 8080:8080 \
  assassinate:latest
```

### Multi-Architecture Builds

```bash
# Build for multiple architectures
docker buildx build -f docker/Dockerfile \
  --platform linux/amd64,linux/arm64 \
  -t assassinate:latest \
  --push ..
```

## CI/CD Integration

### GitHub Actions Example

```yaml
- name: Run tests in Docker
  run: |
    docker compose run --rm test

- name: Build production image
  run: |
    docker compose build assassinate
    docker tag assassinate:latest myregistry/assassinate:${{ github.sha }}
    docker push myregistry/assassinate:${{ github.sha }}
```

## Security Considerations

1. **Non-Root User**: Production container runs as `hitman` (UID 1000)
2. **Minimal Image**: Production image only includes runtime dependencies
3. **Health Checks**: Built-in health checking for all services
4. **Network Isolation**: Services communicate via private network
5. **Secrets**: Use environment variables or Docker secrets for sensitive data

## Performance Optimization

1. **Build Caches**: Cargo and build artifacts are cached in volumes
2. **Layer Caching**: Dockerfile optimized for layer reuse
3. **Multi-Stage**: Builder artifacts not included in production image
4. **Alpine PostgreSQL**: Smaller, faster database image
5. **Volume Mounts**: Development mounts source for instant updates

## Size Comparison

| Image | Size | Use Case |
|-------|------|----------|
| `assassinate:latest` (production) | ~2.5GB | Production deployment |
| `assassinate:dev` (development) | ~3.0GB | Development & testing |
| `postgres:16-alpine` | ~240MB | Database |

## Additional Resources

- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Multi-Stage Builds](https://docs.docker.com/build/building/multi-stage/)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Assassinate Documentation](../README.md)

## Support

For issues or questions:
1. Check this README for troubleshooting steps
2. Review logs: `docker compose logs`
3. Verify installation: `docker compose run --rm test assassinate-setup --verify`
4. Open an issue on GitHub with logs and error messages