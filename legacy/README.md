# legacy: key-amnesia (Python)

This directory holds key-amnesia, the Python predecessor of Vahta, kept for
reference. It is maintained on the `master` branch until its final release on
PyPI. It is not built or tested on this branch.

| Path | What it was |
|------|-------------|
| `src/key_amnesia/` | The Python package |
| `tests/` | Its pytest suite |
| `pyproject.toml`, `MANIFEST.in` | Its packaging |
| `skills/`, `claude-hooks/` | Pointer notes for the agent skills and the hook, which the package shipped itself |

Vahta reads key-amnesia vaults with `vahta import --ka PATH`.
