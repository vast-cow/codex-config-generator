# Codex Permission Profile Generator

Generate a host-specific filesystem allowlist for Codex CLI on Linux and WSL2. Requires Python 3.9 or newer.

```sh
python3 scripts/generate_permission_profile.py
```

The output sets `default_permissions = "generated"`. Use `--name NAME` to change both the generated profile's name and the value of `default_permissions`.

See the [usage guide](docs/permission-profiles.md) for activation, verification, and rollback.
