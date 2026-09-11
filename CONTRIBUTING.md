# Contributing to PyraSec

Thank you for contributing to PyraSec!

## Development Guidelines

### Requirements
- Python 3.10+
- `pytest`, `pytest-cov`, `ruff`, `build`

### Local Verification Workflow

Before submitting a pull request, run all checks locally:

1. **Linting:**
   ```bash
   ruff check .
   ```

2. **Test Suite & Code Coverage (>=80% required):**
   ```bash
   python3 -m pytest --cov=pyrasec --cov-fail-under=80
   ```

3. **Engine Health Check:**
   ```bash
   python3 -m pyrasec health
   ```

4. **Container Build Verification:**
   ```bash
   docker build -t pyrasec:local .
   docker run --rm pyrasec:local health
   ```

## Pull Requests
- Branch from `master`.
- Ensure all CI workflows and CodeQL scans pass.
