# Generate a Codex Permission Profile

Run the generator as the account that runs Codex, from the host and mount namespace where Codex launches its sandbox. Run it outside the existing wrapper so discovery sees the actual host filesystem. The generator uses `HOME`, with the account database as a fallback, and resolves it to an existing directory.

```sh
python3 scripts/generate_permission_profile.py --name isolated
python3 scripts/generate_permission_profile.py --name isolated --validate
python3 scripts/generate_permission_profile.py --name isolated --output isolated.toml
```

The default command prints TOML to stdout. Diagnostics go to stderr and show discovered login-capable accounts and their home paths, skipped non-login accounts, the sorted list of excluded top-level directories, and any warnings. `--output` creates a new file exclusively. `--validate` checks the policy against the discovered homes, mount table, and known Linux `:minimal` paths without writing a file. Effective permissions also depend on Codex and its launch environment.

The output starts with the top-level setting `default_permissions = "generated"` and defines a profile with that name. Use `--name isolated` to set both the selector and the profile name to `isolated`.

## Which homes are protected

Python's `pwd.getpwall()` enumerates the system passwd database through the configured Name Service Switch (NSS) sources. The generator recognizes login shells by exact path in `/etc/shells`. It accepts absolute paths and ignores blank lines, comments, and surrounding whitespace. Shells whose final path component is `nologin`, `false`, `halt`, `shutdown`, or `sync` are treated as non-login shells even when listed. The current `HOME` is always protected, including when its account is missing from the results or has a skipped shell.

An unlisted or empty shell field is reported with the account name and home path. The default, `--unknown-shell protect`, treats these accounts as potentially login-capable and runs their homes through the same checks as recognized login homes. Use `--unknown-shell error` to stop generation at the first unknown shell. If `/etc/shells` is missing or unreadable, the generator warns and applies the selected fallback to all shells other than the known non-login shells. List the exact path of a custom login shell or symlink spelling in `/etc/shells` if you want the generator to recognize it.

Each usable home contributes the first directory below `/` from both its normalized configured path and its symlink-resolved path. For example, `/home/alice` and `/home/bob` contribute `/home`, `/root` contributes `/root`, and `/srv/users/dev` contributes `/srv`. Valid absolute homes that are missing on disk still contribute exclusions, including any resolvable symlink target. Empty or relative paths, paths containing a NUL byte, and paths that refer to a non-directory are skipped with warnings. A home that resolves to `/` or cannot be safely resolved stops generation.

Some NSS backends can look up individual accounts while returning only a subset of accounts during enumeration. A reported lookup error stops generation. An empty result emits a warning and still protects the current HOME. Verify coverage with your account provider and use `--exclude` for any additional home paths or branches.

## Activate and revert

1. Back up your active Codex user configuration before editing it. It is normally `~/.codex/config.toml`, or `$CODEX_HOME/config.toml` when you set `CODEX_HOME`.
2. Append the generated tables under an unused permission profile name. Keep the rest of your configuration. If HOME is symlinked, launch Codex with its canonical HOME so tools can reach the three Codex paths through `$HOME/.codex`.
3. From a trusted, narrowly scoped workspace, start a fresh session with the profile selected. Use the normal Codex Bubblewrap launcher when testing the profile or switching away from the wrapper.

   ```sh
   codex -c 'default_permissions="isolated"' -C /path/to/workspace
   ```

   For persistent selection, copy the generated `default_permissions` line above the first table header in your user config or replace the existing top-level setting. Review existing legacy `sandbox_mode` and `sandbox_workspace_write` settings before selecting a named profile. Avoid passing `--sandbox` at launch because legacy sandbox settings can change which policy is selected. The CLI `--profile` flag selects a configuration layer. [Codex configuration reference](https://developers.openai.com/codex/config-reference)

To revert a one-off selection, exit the session and omit the command-line override. To revert a persistent selection, restore the previous `default_permissions` setting and remove the generated tables. You can also restore your backup if you made no other config edits. Restore the wrapper launcher if you previously used it, and restart Codex.

## Verify effective access

Recent versions expose `codex sandbox -P` to test a saved permission profile without contacting a model. From a disposable workspace, create a harmless marker under HOME outside the workspace and the three Codex exceptions, then pass its absolute path to this probe. The probe assumes the profile included all three Codex exceptions. Remove the checks for any optional paths the generator skipped. If your release uses different syntax, check `codex sandbox --help`.

```sh
codex sandbox -P isolated -C /path/to/workspace -- /bin/sh -ec '
  test ! -e "$1"
  test ! -e "$HOME/.codex/config.toml"
  test -r "$HOME/.codex/packages"
  test ! -w "$HOME/.codex/packages"
  test -r "$HOME/.codex/AGENTS.md"
  test -w "$HOME/.codex/memories"
  for path in . .git .agents .codex .aws; do
    if test -d "$path"; then test -w "$path"; fi
  done
  probe=$(mktemp ./.codex-write-probe.XXXXXXXX)
  rm -- "$probe"
' probe /absolute/path/to/your/home-marker
```

Check that the marker exists outside the sandbox before running the probe and remove it afterward. Confirm that commands can create files in the configured temporary directory and that `apply_patch` works in a fresh session. Older releases may lack explicit workspace metadata overrides, support for restricted-profile startup, or the read grant for the active `apply_patch` alias directory. The generator grants read to the Codex package directory when present. The active launcher alias directory comes from Codex on supported versions. A shell launched with `codex sandbox` can have different runtime paths from an actual session, so verify both if you rely on aliases. [Codex helper grant implementation](https://github.com/openai/codex/blob/main/codex-rs/core/src/config/permissions.rs) · [Restricted profile startup issue](https://github.com/openai/codex/issues/29049)

## Filesystem rules

- The generator discovers real directories directly below `/` and excludes the branches containing the configured or canonical paths of protected homes. It skips top-level symlinks, `/home`, `/root`, `/afs`, `/mnt`, `/media`, and broad grants to `/proc`, `/sys`, `/dev`, and `/run`. Linux Bubblewrap supplies a minimal `/dev` and manages `/proc` itself.
- Linux mountinfo provides the backing device and filesystem-relative path for bind mounts. The generator compares overlapping source paths, including mounts inside protected homes, and skips grants with separate mounts at, below, or above the granted path. Rebinds of the same backing directory at the same path are eligible when they pass the home checks. On WSL the generator excludes the `/mnt` tree even with overrides. Separate Windows drive mounts elsewhere are also excluded, including mounts reported as 9p or drvfs.
- `:minimal` covers `/bin`, `/sbin`, `/usr`, `/etc`, `/lib`, `/lib64`, `/nix/store`, and `/run/current-system/sw` when present. Generation stops if these grants or Linux runtime paths would bypass a home exclusion or mount check. Review the account home and mounts named in the diagnostics before retrying. [Codex Linux mount implementation](https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/src/bwrap.rs)
- The generator uses absolute paths below canonical HOME for the three exceptions. Existing `.codex/packages` and `.codex/AGENTS.md` receive read access and `.codex/memories` receives write access. Missing paths are skipped. The generator rejects a symlinked `.codex` directory and skips unsafe optional entries, including paths that expose a different account home through a mount alias. Accounts with the same canonical HOME share these exceptions. An exact regular-file mount for `AGENTS.md` is eligible, which lets you bind a shared instructions file.
- `:workspace_roots` grants write access to each workspace and explicitly grants write access to its `.git`, `.agents`, `.codex`, and `.aws` entries. Workspace grants are resolved by Codex at launch, so select roots that do not contain HOME or unrelated user data. Review workspace mounts, symlinks, Git worktree metadata, and additional roots before using the profile.

Use `--include DIR` for an existing absolute directory that would otherwise be omitted and `--exclude PATH` to omit overlapping grants. Both flags are repeatable. Excluding a descendant removes the whole overlapping directory grant. You can then include narrower sibling directories explicitly if they pass the home branch, symlink, and mount checks.

```sh
python3 scripts/generate_permission_profile.py \
  --exclude /var/lib/private --include /var/log --temp none
```

Temporary access defaults to `--temp auto`. It grants `:slash_tmp` write access when `/tmp` passes the checks, including a standalone `/tmp` tmpfs. If `/tmp` is unsafe, the generator emits a diagnostic and omits the grant. Use `--temp slash-tmp` to require that grant, or `--temp none` to omit it. To use a narrower directory, create an existing private directory that does not overlap a protected home or its mount aliases, pass it to `--temp-dir`, and set `TMPDIR` for the sandboxed commands that use it. The profile binds this exact path even if a later process changes its `TMPDIR`.

```sh
scratch=$(mktemp -d /tmp/codex-work.XXXXXXXX)
python3 scripts/generate_permission_profile.py --name isolated --temp-dir "$scratch"
```

After adding the resulting profile to your configuration, launch Codex with `TMPDIR="$scratch"` or set that value in the commands that need temporary storage. Keep the directory for as long as the profile refers to it.

## Wrapper differences and limitations

This replaces the wrapper's HOME isolation, selected Codex data grants, and workspace metadata write behavior at the permission-policy level. Codex builds its own sandbox filesystem with an allowlist and synthetic directories. This avoids the denied-parent behavior reported in issue #54565. Arbitrary Bubblewrap argument rewriting, custom mount operations, and wrapper-specific environment and launcher changes require a wrapper. Process isolation, networking, and WSL interoperability depend on the Codex release and its settings. The generated Codex data exceptions assume the default `~/.codex` location. Review a custom `CODEX_HOME` separately, especially when it is outside HOME and under an allowed root. [Linux denied-parent issue](https://github.com/openai/codex/issues/54565)

The mount table and path checks describe a snapshot. New or changed mounts, moved HOME directories, filesystem snapshots, hard links, copied data, and other paths intentionally made readable can expose data outside its canonical HOME path. Generate again after host layout changes and verify from the production launch environment. The generator also depends on the installed Codex release's implicit runtime grants and enforcement. A Bubblewrap fallback that retains inherited procfs has a different process-visibility surface from a fresh procfs. Keep sensitive files out of approved workspace roots and other readable directories.

## Run tests

Use Python 3.11 or newer for the tests, which parse the generated output with `tomllib`.

```sh
python3.11 -B -m unittest discover -s tests -v
```

The fixture tests never edit your Codex configuration. The Bubblewrap integration test applies generated grants to fixture mounts and checks effective read and write access. It skips when Bubblewrap or the required namespaces are unavailable.
