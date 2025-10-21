# Repository Guidelines
This guide describes standards for contributing to IAMLeastPrivilegeGenerator so new automation stays consistent and secure.

## Project Structure & Module Organization
The main branch currently holds only high-level docs; add generator logic under `src/` with IAM builders in `src/policies/`, cloud adapters in `src/providers/`, and CLI wiring in `src/cli/`. Store example JSON/YAML outputs in `examples/`, shared configuration in `config/`, and deployment assets in `templates/`. Keep fast tests in `tests/unit/`, scenario tests in `tests/integration/`, and keep helpers small so policy changes stay traceable.

## Build, Test, and Development Commands
Create an isolated environment before developing: `python -m venv .venv` then `source .venv/bin/activate`. Install dependencies with `pip install -r requirements.txt` once the file is populated. Use `pytest` for the full test suite and `pytest tests/unit -k policy` while iterating on a specific behavior. Run `python -m iam_generator.cli --help` to validate the CLI wiring.

## Coding Style & Naming Conventions
Adopt Python 3.11+, enforcing 4-space indentation, type hints on public functions, and concise docstrings for AWS-facing code. Name modules with lowercase underscores (`src/policies/s3_bucket.py`), classes in PascalCase, and functions in snake_case verbs. Run `ruff check` and `ruff format` (via pre-commit) before pushing. Prefix IAM template filenames with the service (`s3_readonly.json`).

## Testing Guidelines
Use pytest fixtures to mock AWS responses via `moto` or `botocore.stub`. Name tests `test_<unit_under_test>_<result>` to keep reports searchable. Target at least 85% coverage, with every new IAM policy generator backed by a unit test for statement shape, a snapshot in `tests/data/`, and an integration check that enforces least-privilege expectations. Document skipped tests inline with a reason and link to an issue.

## Commit & Pull Request Guidelines
Write commits in the imperative mood (`Add S3 policy generator`) and keep them scoped to one topic. Reference relevant tickets in the body. Pull requests should explain the IAM risk mitigated, list testing commands executed, attach sample policy output without secrets, and tag a reviewer familiar with the target AWS service.

## Security & Configuration Tips
Never commit AWS credentials; rely on environment variables or profile names referenced in `~/.aws/credentials`. Store red-team or customer data in encrypted fixtures only. Treat new permissions as suspect until validated by Access Analyzer and least-privilege scans. When adding configuration flags, document their default value and failure modes in `README.md` so operators understand the blast radius.
