#!/usr/bin/env python3
"""Generate a host-specific, allowlist-only Codex profile for Linux and WSL."""

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat
import sys


ROOT = Path("/")
# Codex's LINUX_PLATFORM_DEFAULT_READ_ROOTS in linux-sandbox/src/bwrap.rs.
MINIMAL_ROOTS = (
    "/bin", "/sbin", "/usr", "/etc", "/lib", "/lib64", "/nix/store",
    "/run/current-system/sw",
)
# Codex creates a minimal /dev and may mount a new or inherited /proc.
RUNTIME_ROOTS = ("/dev", "/proc")
DEFAULT_OMISSIONS = {
    "afs", "dev", "home", "media", "mnt", "proc", "root", "run", "sys", "tmp",
}
CODEX_PATHS = (
    ("packages", "read", stat.S_ISDIR),
    ("memories", "write", stat.S_ISDIR),
    ("AGENTS.md", "read", stat.S_ISREG),
)
WORKSPACE = dict.fromkeys((".", ".git", ".agents", ".codex", ".aws"), "write")


def overlap(first, second):
    return first.is_relative_to(second) or second.is_relative_to(first)


def mount_path(field):
    # mountinfo escapes whitespace and backslashes with three octal digits.
    return Path(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), field))


@dataclass(frozen=True)
class Mount:
    device: str
    source: Path  # Directory relative to the filesystem root, not a host path.
    target: Path
    filesystem: str

    def backing_path(self, path):
        return self.source / path.relative_to(self.target)


def parse_mountinfo(text):
    mounts = []
    for line in text.rstrip("\n").split("\n"):
        fields, separator, detail = line.partition(" - ")
        fields, detail = fields.split(" "), detail.split(" ")
        if not separator or len(fields) < 6 or len(detail) < 3:
            raise ValueError("invalid /proc/self/mountinfo entry")
        target = mount_path(fields[4])
        if not target.is_absolute() or not re.fullmatch(r"[0-9]+:[0-9]+", fields[2]):
            raise ValueError("invalid mountinfo target or device number")
        # nsfs roots may be identifiers like net:[4026531840].
        mounts.append(Mount(fields[2], mount_path(fields[3]), target, detail[0]))
    if not any(mount.target == ROOT for mount in mounts):
        raise ValueError("mountinfo has no root filesystem")
    return mounts


def directory_path(value):
    path = Path(value)
    if path.anchor != "/" or ".." in path.parts:
        raise ValueError(f"expected an absolute path without '..': {value!r}")
    return path


def literal_path(path):
    value = str(path)
    return not any(char in value for char in "*?[]") and all(
        not 0xD800 <= ord(char) <= 0xDFFF for char in value
    )


@dataclass
class Profile:
    name: str
    grants: dict[str, str]
    notices: list[str]

    def toml(self):
        name = quote(self.name)
        prefix = f"permissions.{name}"
        lines = [f"default_permissions = {name}", "", f"[{prefix}]", f"[{prefix}.filesystem]", ""]
        lines.extend(f'{quote(path)} = "{access}"' for path, access in self.grants.items())
        lines.extend(("", f'[{prefix}.filesystem.":workspace_roots"]'))
        lines.extend(f'{quote(path)} = "{access}"' for path, access in WORKSPACE.items())
        return "\n".join(lines) + "\n"


def quote(value):
    # JSON's basic string escapes are accepted by TOML. TOML also escapes DEL.
    return json.dumps(value, ensure_ascii=False).replace("\x7f", r"\u007f")


def is_wsl(release, environment):
    return "microsoft" in release.lower() or bool(
        environment.get("WSL_DISTRO_NAME") or environment.get("WSL_INTEROP")
    )


class Host:
    def __init__(self, root, home, mounts, wsl=False):
        self.root = root  # The caller can supply a fixture root for tests.
        self.mounts = mounts
        self.wsl = wsl
        if home.anchor not in ("/", "//"):
            raise ValueError("HOME must be absolute")
        self.home = self.canonical(home)
        self.logical_home = Path("/" + os.path.normpath(home).lstrip("/"))
        if self.home == ROOT or self.logical_home == ROOT or not self.real(self.home).is_dir():
            raise ValueError("HOME must be an existing directory beneath /")
        self.home_backings = {
            (mount.device, backing)
            for mount in mounts
            if (backing := self.backing_slice(mount, self.home)) is not None
        }
        # A separate mount may be an innocuous rebinding of the same directory
        # at the same path (for example a container making /tmp writable).
        self.other_mounts = [
            mount for mount in mounts if mount.target != ROOT and not any(
                parent.device == mount.device
                and mount.target != parent.target
                and mount.target.is_relative_to(parent.target)
                and mount.source == parent.backing_path(mount.target)
                for parent in mounts
            )
        ]

    def real(self, path):
        return self.root.joinpath(*path.parts[1:])

    def canonical(self, path):
        return ROOT / self.real(path).resolve(strict=True).relative_to(self.root)

    @staticmethod
    def backing_slice(mount, path):
        if path.is_relative_to(mount.target):
            return mount.backing_path(path)
        if mount.target.is_relative_to(path):
            return mount.source
        return None

    def home_conflict(self, path):
        if any(overlap(path, home) for home in (self.home, self.logical_home)):
            return True
        # Include covering and nested mounts on both sides. Keep shadowed
        # backing paths too, since another bind can expose those paths.
        for mount in self.mounts:
            backing = self.backing_slice(mount, path)
            if backing is not None and any(
                mount.device == device and overlap(backing, private)
                for device, private in self.home_backings
            ):
                return True
        return False

    def read_conflict(self, path, excludes, *, temporary=False):
        if self.home_conflict(path):
            return "overlaps HOME or a mounted alias of HOME"
        if any(overlap(path, excluded) for excluded in excludes):
            return "overlaps an excluded path"
        if self.wsl and overlap(path, Path("/mnt")):
            return "overlaps the WSL mount tree /mnt"
        for mount in self.other_mounts:
            if not overlap(path, mount.target):
                continue
            # A dedicated /tmp tmpfs is a normal Linux setup. Check for HOME
            # aliases above and continue checking every other nested mount.
            if (temporary and mount.target == Path("/tmp") and
                    mount.filesystem == "tmpfs" and mount.source == ROOT):
                continue
            return f"intersects a separate mount at {str(mount.target)!r}"
        return None

    def directory_conflict(self, path, excludes, *, temporary=False):
        if path == ROOT:
            return "the filesystem root cannot be granted"
        if not literal_path(path):
            return "Codex requires a literal UTF-8 path without glob characters"
        if any(overlap(path, Path(special)) for special in (*RUNTIME_ROOTS, "/sys")):
            return "overlaps a kernel filesystem"
        reason = self.read_conflict(path, excludes, temporary=temporary)
        if reason:
            return reason
        if self.canonical(path) != path or not self.real(path).is_dir():
            return "expected a real directory with no symlink components"
        return None

    def validate_minimal(self, excludes):
        for value in RUNTIME_ROOTS:
            path = Path(value)
            if self.home_conflict(path):
                raise ValueError(f"HOME overlaps the Linux runtime path {value}")
            if any(overlap(path, excluded) for excluded in excludes):
                raise ValueError(f"cannot exclude the Linux runtime path {value}")
        for value in MINIMAL_ROOTS:
            path = Path(value)
            try:
                canonical = self.canonical(path)
            except FileNotFoundError:
                continue
            for candidate in (path, canonical):
                reason = self.read_conflict(candidate, excludes)
                if reason:
                    raise ValueError(f":minimal implicitly grants {value}: {reason}")

    def codex_grants(self, excludes, notices):
        codex = self.home / ".codex"
        try:
            mode = self.real(codex).lstat().st_mode
        except FileNotFoundError:
            return
        if not stat.S_ISDIR(mode) or any(mount.target == codex for mount in self.other_mounts):
            raise ValueError(f"expected a real directory at {str(codex)!r}")
        for name, access, expected_type in CODEX_PATHS:
            path = codex / name
            if any(overlap(path, excluded) for excluded in excludes):
                continue
            try:
                mode = self.real(path).lstat().st_mode
            except FileNotFoundError:
                continue
            # An exact file mount can be an intentional AGENTS.md grant. A
            # recursive mount below a Codex directory could expose other data.
            foreign_mount = any(
                mount.target.is_relative_to(path) and
                (mount.target != path or stat.S_ISDIR(mode))
                for mount in self.other_mounts
            )
            if not expected_type(mode) or foreign_mount or not literal_path(path):
                notices.append(f"skipping unsafe optional Codex path {str(path)!r}")
                continue
            yield str(path), access


def generate(host, name="generated", include=(), exclude=(), temp="auto", temp_dir=None):
    if not name.strip() or name.startswith(":"):
        raise ValueError("profile name must be nonempty, without a leading ':'")
    name.encode("utf-8")
    excludes = {directory_path(value) for value in exclude}
    excludes.update(host.canonical(path) for path in tuple(excludes)
                    if host.real(path).exists())
    host.validate_minimal(excludes)

    # Exclude both branches if HOME was reached via a symlink.
    omitted = DEFAULT_OMISSIONS | {host.home.parts[1], host.logical_home.parts[1]}
    directories = set()
    for child in host.root.iterdir():
        path = ROOT / child.name
        # Check the mount table before touching a potentially automounted
        # child. lstat identifies directories without resolving symlinks.
        if (child.name not in omitted and literal_path(path)
                and not host.read_conflict(path, excludes)
                and stat.S_ISDIR(child.lstat().st_mode)):
            directories.add(path)
    for value in include:
        path = directory_path(value)
        reason = host.directory_conflict(path, excludes)
        if reason:
            raise ValueError(f"cannot include {value!r}: {reason}")
        directories.add(path)

    notices = []
    grants = {":minimal": "read"}
    grants.update((str(path), "read") for path in sorted(directories))
    grants.update(host.codex_grants(excludes, notices))
    if temp_dir is not None or temp != "none":
        path = directory_path(temp_dir) if temp_dir is not None else Path("/tmp")
        try:
            reason = host.directory_conflict(path, excludes, temporary=True)
        except FileNotFoundError:
            reason = "directory does not exist"
        if reason:
            message = f"temporary write grant for {str(path)!r}: {reason}"
            if temp_dir is not None or temp == "slash-tmp":
                raise ValueError(message)
            notices.append(f"omitting {message}")
        else:
            key = str(path) if temp_dir is not None else ":slash_tmp"
            grants[key] = "write"
            if key == ":slash_tmp":
                grants.pop(str(path), None)

    return Profile(name, grants, notices)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="generated",
                        help="permission profile name used for default_permissions (default: %(default)s)")
    parser.add_argument("--include", action="append", default=[], metavar="DIR",
                        help="add an existing absolute directory as read-only (repeatable)")
    parser.add_argument("--exclude", action="append", default=[], metavar="PATH",
                        help="omit grants overlapping an absolute path (repeatable)")
    temporary = parser.add_mutually_exclusive_group()
    temporary.add_argument("--temp", choices=("auto", "slash-tmp", "none"), default="auto",
                           help="grant safe /tmp, require /tmp, or omit temp access")
    temporary.add_argument("--temp-dir", metavar="DIR",
                           help="grant write to a specific existing absolute directory")
    destination = parser.add_mutually_exclusive_group()
    destination.add_argument("-o", "--output", type=Path,
                             help="create a new file instead of printing to stdout")
    destination.add_argument("--validate", action="store_true",
                             help="check the generated policy against this host without writing")
    args = parser.parse_args(argv)

    try:
        if sys.platform != "linux":
            raise ValueError("this generator requires Linux or WSL2")
        mountinfo = Path("/proc/self/mountinfo")
        snapshot = mountinfo.read_bytes()
        mounts = parse_mountinfo(snapshot.decode("utf-8", errors="surrogateescape"))
        host = Host(ROOT, Path.home(), mounts, is_wsl(os.uname().release, os.environ))
        profile = generate(host, args.name, args.include, args.exclude, args.temp, args.temp_dir)
        if mountinfo.read_bytes() != snapshot:
            raise ValueError("mount table changed during discovery, rerun the generator")
        rendered = profile.toml()
        for notice in profile.notices:
            print(f"warning: {notice}", file=sys.stderr)
        if args.validate:
            print(f"Validated {profile.name!r} for HOME {str(host.home)!r} "
                  f"({len(profile.grants)} filesystem grants plus workspace rules).")
        elif args.output:
            with args.output.open("x", encoding="utf-8") as output:
                output.write(rendered)
        else:
            sys.stdout.write(rendered)
    except (OSError, RuntimeError, ValueError) as error:
        parser.exit(1, f"{parser.prog}: {error}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
