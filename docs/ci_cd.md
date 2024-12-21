# CI/CD Pipeline Overview

## Workflow Jobs

### Linting
- Tools: `flake8`, `black`, `mypy`
- Ensures code adheres to style and type-checking standards.

### Build C Library
- Compiles `metasploit_core.c` into `metasploit_core.so`.
- Validates the shared library is generated.

### Run Python Tests
- Executes all unit and integration tests.
- Location: `python/tests/`

### Documentation
- Builds project documentation using Sphinx.
- Output: `docs/_build/html`

## Triggering Workflows
- **On Push:** Any push to the `main` branch.
- **On Pull Request:** Any PR targeting `main`.

## Monitoring CI/CD
- Go to the **Actions** tab in your GitHub repository.
- Check each job for status and logs.
