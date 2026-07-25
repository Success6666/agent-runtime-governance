# Contributing

Thanks for improving Agent Runtime Governance. The project uses the same flow
for maintainers and external contributors: issue first, pull request second,
merge only after required checks and review are complete.

## Workflow

1. Open or claim an issue that describes the bug, feature, or documentation
   change.
2. Create a branch from `main`; do not push directly to `main`.
3. Keep commits focused. Prefer small commits such as `fix: propagate otel span
   into sync tools` over one large mixed commit.
4. Open a pull request with a closing keyword such as `Fixes #123`.
5. Wait for CI, integration smoke, CodeRabbit, and required review checks.
6. Resolve review threads before merge.

Unlinked pull requests are closed automatically. Administrators are protected by
the same branch rules as everyone else.

## Local validation

```bash
python -m pip install -e ".[dev,otel,yaml,prometheus]"
ruff check .
pytest --cov=agent_runtime_governance --cov-report=term-missing
python integration/production_smoke.py --skip-kind
python -m build
```

Run the full smoke when Docker, Kind, and kubectl are available:

```bash
python integration/production_smoke.py
```

## Plugin contributions

Plugin contributions must keep the runtime immutable and fail closed for
authorization decisions.

- Register middleware or services through `RuntimeBuilder`.
- Do not download or execute remote plugin code at runtime.
- Validate URLs, headers, payload sizes, and external response schemas.
- Keep metric labels low-cardinality and free of user, tenant, trace, path, or
  secret values.
- Add unit tests plus an integration or smoke test when the plugin talks to an
  external process.

## Pull request description

Use the repository template and keep it factual:

- Summary
- Fixes issue
- Tests

Do not include generated logs, secrets, local cache files, virtual environments,
or unrelated formatter churn.
