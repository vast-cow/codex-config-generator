import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from scripts.generate_permission_profile import (
    Host, WORKSPACE, generate, is_wsl, parse_mountinfo,
)


ROOT_MOUNT = "1 0 8:1 / / rw - ext4 /dev/test rw"
SCRIPT = Path(__file__).resolve().parents[1] / "scripts/generate_permission_profile.py"


class ProfileTests(unittest.TestCase):
    def setUp(self):
        fixture = tempfile.TemporaryDirectory()
        self.addCleanup(fixture.cleanup)
        self.root = Path(fixture.name).resolve()
        for directory in ("home/alice", "root", "users/alice", "opt", "usr/bin",
                          "etc", "tmp", "var", "proc", "sys", "dev", "run"):
            self.make_directory(directory)

    def make_directory(self, path):
        directory = self.root / path.lstrip("/")
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def host(self, home="/home/alice", mounts="", **kwargs):
        return Host(self.root, Path(home), parse_mountinfo(f"{ROOT_MOUNT}\n{mounts}"), **kwargs)

    def add_codex_paths(self):
        codex = self.make_directory("home/alice/.codex")
        (codex / "packages").mkdir()
        (codex / "memories").mkdir()
        (codex / "tmp").mkdir()
        (codex / "AGENTS.md").write_text("fixture", encoding="utf-8")
        (codex / "config.toml").touch()
        return codex

    def test_discovers_directories_and_excludes_home_branch(self):
        self.make_directory("unusual")
        (self.root / "top-level-file").touch()
        for home, branch in (("/home/alice", "/home"), ("/root", "/root"),
                             ("/users/alice", "/users")):
            with self.subTest(home=home):
                grants = generate(self.host(home)).grants
                self.assertNotIn(branch, grants)
                self.assertEqual(grants["/unusual"], "read")
                self.assertEqual(grants["/opt"], "read")
                self.assertNotIn("/top-level-file", grants)
                for special in ("/dev", "/proc", "/sys", "/run", "/home", "/root", "/tmp"):
                    self.assertNotIn(special, grants)
        self.assertIn("/users", generate(self.host()).grants)

    def test_symlinked_home_and_top_level_aliases(self):
        self.make_directory("real/alice")
        self.make_directory("logical")
        (self.root / "logical/alice").symlink_to("../real/alice")
        (self.root / "alias").symlink_to("real")
        (self.root / "bin").symlink_to("usr/bin")
        (self.root / "broken").symlink_to("does-not-exist")
        host = self.host("/logical/alice")
        self.assertEqual(host.home, Path("/real/alice"))
        grants = generate(host).grants
        for path in ("/alias", "/logical", "/real", "/bin", "/broken"):
            self.assertNotIn(path, grants)
        with self.assertRaisesRegex(ValueError, "no symlink components"):
            generate(host, include=["/alias"])

    def test_bind_mounts_to_home_and_backing_source_are_excluded(self):
        self.make_directory("backup")
        self.make_directory("var/mirror")
        self.make_directory("export/people/alice")
        host = self.host(mounts=(
            "2 1 8:1 /export/people/alice /home/alice rw - ext4 /dev/test rw\n"
            "3 1 8:1 /home /backup rw - ext4 /dev/test rw\n"
            "4 1 8:1 /export/people/alice/private /var/mirror rw - ext4 /dev/test rw\n"
        ))
        grants = generate(host).grants
        for path in ("/backup", "/var", "/export"):
            self.assertNotIn(path, grants)
            with self.assertRaisesRegex(ValueError, "mounted alias of HOME"):
                generate(host, include=[path])
        self.make_directory("var/empty")
        self.assertEqual(generate(host, include=["/var/empty"]).grants["/var/empty"], "read")

    def test_mounted_subtree_inside_home_is_protected_at_its_source(self):
        host = self.host(mounts="2 1 8:1 /opt/private /home/alice/secret rw - ext4 disk rw")
        self.assertNotIn("/opt", generate(host).grants)

    def test_mountinfo_decodes_paths_and_accepts_namespace_mounts(self):
        mounts = parse_mountinfo(
            ROOT_MOUNT + "\n"
            r"2 1 8:1 /home/my\040dir /backup\134old rw - ext4 disk rw" + "\n"
            "3 1 0:1 net:[12] /run/ns rw - nsfs nsfs rw"
        )
        self.assertEqual(mounts[1].target, Path(r"/backup\old"))
        self.assertEqual(mounts[1].source, Path("/home/my dir"))
        self.assertEqual(mounts[2].source, Path("net:[12]"))
        with self.assertRaisesRegex(ValueError, "no root filesystem"):
            parse_mountinfo("3 1 0:1 net:[12] /run/ns rw - nsfs nsfs rw")

    def test_missing_optional_codex_paths(self):
        self.assertFalse(any(".codex/" in path for path in generate(self.host()).grants))
        self.make_directory("home/alice/.codex/packages")
        grants = generate(self.host()).grants
        self.assertEqual(grants["/home/alice/.codex/packages"], "read")
        self.assertNotIn("/home/alice/.codex/AGENTS.md", grants)
        self.assertNotIn("/home/alice/.codex/memories", grants)

    def test_unsafe_codex_paths(self):
        codex = self.add_codex_paths()
        (codex / "AGENTS.md").unlink()
        (codex / "AGENTS.md").symlink_to("../../secret")
        host = self.host(mounts=(
            "2 1 8:1 /home/alice/private /home/alice/.codex/packages rw - ext4 disk rw"
        ))
        profile = generate(host)
        self.assertNotIn("/home/alice/.codex/AGENTS.md", profile.grants)
        self.assertNotIn("/home/alice/.codex/packages", profile.grants)
        self.assertEqual(len(profile.notices), 2)

    def test_symlinked_codex_directory_fails(self):
        self.make_directory("opt/codex")
        (self.root / "home/alice/.codex").symlink_to("../../opt/codex")
        with self.assertRaisesRegex(ValueError, "expected a real directory"):
            generate(self.host())

    def test_toml_round_trip_and_grants(self):
        self.add_codex_paths()
        name = 'work."local" \\ 日本\n\x7f'
        unusual = '/data."quotes" \\ ü\t\x7f'
        self.make_directory(unusual)
        self.make_directory("glob[abc]")
        parsed = tomllib.loads(generate(self.host(), name).toml())
        profile = parsed["permissions"][name]
        self.assertEqual(set(profile), {"filesystem"})
        fs = profile["filesystem"]
        self.assertEqual(fs[":minimal"], "read")
        self.assertEqual(fs[unusual], "read")
        self.assertEqual(fs[":slash_tmp"], "write")
        self.assertEqual(fs[":workspace_roots"], {
            ".": "write", ".git": "write", ".agents": "write",
            ".codex": "write", ".aws": "write",
        })
        self.assertEqual({path: mode for path, mode in fs.items() if ".codex/" in path}, {
            "/home/alice/.codex/packages": "read",
            "/home/alice/.codex/memories": "write",
            "/home/alice/.codex/AGENTS.md": "read",
        })
        for path in ("/", ":root", ":workspace", "/glob[abc]", "/home/alice/.codex"):
            self.assertNotIn(path, fs)
        self.assertNotIn("deny", fs.values())
        for name in ("", "  ", ":workspace"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "profile name"):
                generate(self.host(), name)

    def test_wsl_detection_and_drive_mounts(self):
        self.assertTrue(is_wsl("6.6.87.2-microsoft-standard-WSL2", {}))
        self.assertTrue(is_wsl("custom", {"WSL_DISTRO_NAME": "Ubuntu"}))
        self.assertFalse(is_wsl("6.12.0", {}))
        self.make_directory("mnt/c")
        self.make_directory("windows/c")
        self.make_directory("opt/c")
        for filesystem in ("9p", "drvfs"):
            with self.subTest(filesystem=filesystem):
                host = self.host(wsl=True, mounts=(
                    f"2 1 0:1 / /windows/c rw - {filesystem} C:\\ rw\n"
                    "3 1 0:2 / /opt/c rw - 9p C:\\ rw"
                ))
                grants = generate(host).grants
                for path in ("/mnt", "/windows", "/opt"):
                    self.assertNotIn(path, grants)
                for path in ("/mnt/c", "/windows/c", "/opt/c"):
                    with self.assertRaisesRegex(ValueError, "WSL mount tree|separate mount"):
                        generate(host, include=[path])
                self.assertIn("/mnt/c", generate(self.host(), include=["/mnt/c"]).grants)

    def test_minimal_home_conflicts(self):
        for home in ("/usr/local/home", "/etc/people/alice", "/nix/store/alice",
                     "/run/current-system/sw/home", "/dev/home", "/proc/home"):
            self.make_directory(home)
            with self.subTest(home=home), self.assertRaisesRegex(ValueError, "HOME"):
                generate(self.host(home))
        (self.root / "bin").symlink_to("home/alice")
        with self.assertRaisesRegex(ValueError, ":minimal implicitly grants /bin"):
            generate(self.host())

    def test_minimal_mount_alias_and_exclusion_conflicts(self):
        host = self.host(mounts="2 1 8:1 /home/alice /usr/private rw - ext4 disk rw")
        with self.assertRaisesRegex(ValueError, ":minimal.*mounted alias"):
            generate(host)
        with self.assertRaisesRegex(ValueError, ":minimal.*excluded path"):
            generate(self.host(), exclude=["/usr/private"])
        with self.assertRaisesRegex(ValueError, "Linux runtime path"):
            generate(self.host(), exclude=["/proc"])

    def test_overrides_and_temporary_modes(self):
        self.make_directory("media/shared")
        self.make_directory("tmp/isolated")
        host = self.host()
        grants = generate(host, include=["/media/shared"], exclude=["/var/secret"],
                          temp_dir="/tmp/isolated").grants
        self.assertNotIn("/var", grants)
        self.assertNotIn(":slash_tmp", grants)
        self.assertEqual(grants["/media/shared"], "read")
        self.assertEqual(grants["/tmp/isolated"], "write")
        self.assertNotIn(":slash_tmp", generate(host, temp="none").grants)
        for path in ("/", "/home/alice", "relative", "/tmp/../usr"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                generate(host, include=[path])
        with self.assertRaisesRegex(ValueError, "excluded path"):
            generate(host, include=["/var"], exclude=["/var/secret"])
        with self.assertRaisesRegex(ValueError, "overlaps HOME"):
            generate(host, temp_dir="/home/alice")

    def test_mounted_temp_and_narrow_fallback(self):
        self.make_directory("tmp/private-tmp")
        host = self.host(mounts="2 1 0:1 / /tmp rw - tmpfs tmpfs rw")
        self.assertEqual(generate(host).grants[":slash_tmp"], "write")
        host = self.host(mounts=(
            "2 1 0:1 / /tmp rw - tmpfs tmpfs rw\n"
            "3 2 8:1 /home/alice /tmp/alias rw - ext4 disk rw"
        ))
        profile = generate(host)
        self.assertNotIn(":slash_tmp", profile.grants)
        self.assertTrue(profile.notices)
        with self.assertRaisesRegex(ValueError, "mounted alias"):
            generate(host, temp="slash-tmp")
        self.assertEqual(generate(host, temp_dir="/tmp/private-tmp").grants["/tmp/private-tmp"],
                         "write")

    def test_deterministic_discovery_order(self):
        host = self.host()
        expected = generate(host).toml()
        entries = list(self.root.iterdir())
        with patch.object(Path, "iterdir", return_value=iter(reversed(entries))):
            self.assertEqual(generate(host).toml(), expected)

    def test_cli_validate_stdout_and_no_clobber_output(self):
        output = self.root / "profile.toml"
        env = dict(os.environ, HOME=str(self.root / "home/alice"))
        command = [sys.executable, str(SCRIPT), "--temp", "none", "--name", "cli-test"]

        def run(*args):
            return subprocess.run([*command, *args], env=env, capture_output=True,
                                  text=True, timeout=15)

        preview = run()
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertIn("cli-test", tomllib.loads(preview.stdout)["permissions"])
        checked = run("--validate")
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn("Validated 'cli-test'", checked.stdout)
        self.assertFalse(output.exists())
        written = run("--output", str(output))
        self.assertEqual(written.returncode, 0, written.stderr)
        self.assertEqual(output.read_text(encoding="utf-8"), preview.stdout)
        self.assertNotEqual(run("--output", str(output)).returncode, 0)
        self.assertEqual(output.read_text(encoding="utf-8"), preview.stdout)

    def test_bubblewrap_visibility(self):
        bwrap = shutil.which("bwrap")
        if not bwrap:
            self.skipTest("Bubblewrap is unavailable")
        base = [bwrap, "--unshare-user", "--unshare-pid"]
        probe = subprocess.run([*base, "--ro-bind", "/", "/", "--", "/bin/true"],
                               capture_output=True, text=True, timeout=15)
        if probe.returncode:
            self.skipTest(f"Bubblewrap namespaces unavailable: {probe.stderr.strip()}")

        codex = self.add_codex_paths()
        (codex / "packages/example").touch()
        (codex.parent / "private").touch()
        (self.root / "opt/home-alias").symlink_to("/fixture/home/alice")
        (self.root / "opt/visible").touch()
        workspace = self.make_directory("home/alice/work")
        for directory in WORKSPACE.keys() - {"."}:
            (workspace / directory).mkdir()
        profile = generate(self.host())
        args = [*base, "--tmpfs", "/", "--dev", "/dev"]
        for path in ("/usr", "/bin", "/lib", "/lib64"):
            if Path(path).is_dir():
                args.extend(("--ro-bind", path, path))
        for path, access in profile.grants.items():
            if path == ":minimal":
                continue
            logical = "/tmp" if path == ":slash_tmp" else path
            real = self.root / logical.lstrip("/")
            flag = "--bind" if access == "write" else "--ro-bind"
            args.extend((flag, str(real), f"/fixture{logical}"))
        for path in WORKSPACE:
            args.extend(("--bind", str(workspace / path), f"/fixture/home/alice/work/{path}"))
        checks = """
            set -eu
            cd /fixture/home/alice
            test ! -e private
            test ! -e /fixture/opt/home-alias/private
            test ! -e .codex/config.toml
            test ! -e .codex/tmp
            test -r .codex/packages/example
            test -r .codex/AGENTS.md
            test -r /fixture/opt/visible
            if (echo wrong > .codex/packages/new) 2>/dev/null; then exit 1; fi
            if (echo wrong > .codex/AGENTS.md) 2>/dev/null; then exit 1; fi
            echo ok > .codex/memories/new
            echo ok > /fixture/tmp/new
            for path in . .git .agents .codex .aws; do
                echo ok > "work/$path/new"
            done
        """
        result = subprocess.run([*args, "--", "/bin/sh", "-c", checks],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((codex / "memories/new").is_file())
        self.assertTrue((self.root / "tmp/new").is_file())


if __name__ == "__main__":
    unittest.main()
