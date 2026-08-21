# Contributing

Leakscan accepts focused bug fixes and improvements through GitHub issues and pull requests. By submitting a contribution, you agree that the project owner may use it as part of this all-rights-reserved project. Submission does not grant broader rights to the repository.

## Development setup

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Before opening a pull request, run:

```powershell
ruff check .
pytest
python -m build
twine check dist\*
```

Keep target-specific data in a case YAML. Do not add organization names, item IDs, filenames, account names, or investigation-specific matching rules to the generic engine. Do not commit API keys, authentication cookies, case output, retrieved evidence, or sensitive personal data.

Changes to network behavior should preserve request limits, robots handling, per-host throttling, resumable state, and the rule that archive-like bodies are not downloaded.
