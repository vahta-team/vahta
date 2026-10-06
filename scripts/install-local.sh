#!/usr/bin/env bash
# Install vahta (and its short name vh) and vahta-hook from this checkout, for
# daily use on this machine.
#
# Linux and macOS. Windows is out of scope for now.
#
# This is not a release: nothing is published anywhere. It builds the Rust
# binaries and copies them into a directory you own, then points the harnesses
# that already run vahta-hook at the installed copy.
#
#   scripts/install-local.sh [--prefix DIR] [--no-setup]
#   scripts/install-local.sh [--prefix DIR] --uninstall [--force]
#
# Run it from anywhere; it finds the repository from its own location.

set -euo pipefail

usage() {
  cat <<'USAGE'
usage: install-local.sh [--prefix DIR] [--no-setup]
       install-local.sh [--prefix DIR] --uninstall [--force]

Build vahta, vh (the short name of vahta) and vahta-hook from this checkout
and install them.

options:
  --prefix DIR   install into DIR (default: ${XDG_BIN_HOME:-$HOME/.local/bin});
                 created if missing
  --no-setup     do not run `vahta setup --refresh` or print the setup table
  --uninstall    remove vahta, vh and vahta-hook from the prefix. Refuses while a
                 harness config still points at the prefix, unless --force
  --force        with --uninstall: remove the binaries anyway
  -h, --help     show this help

Each binary is copied to a temporary file in the prefix and renamed over the
target, so a harness that is running the hook at that moment is not disturbed.
vahta-hook goes in before vahta and vh.

After installing, `vahta setup --refresh` repoints every harness that already
has vahta entries at the installed hook; harnesses without any are left alone.
USAGE
}

die() {
  echo "install-local: error: $*" >&2
  exit 1
}

prefix="${XDG_BIN_HOME:-${HOME:-}/.local/bin}"
setup=1
uninstall=0
force=0

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)
      [ $# -ge 2 ] || die "--prefix needs a directory"
      prefix="$2"
      shift 2
      ;;
    --prefix=*)
      prefix="${1#--prefix=}"
      shift
      ;;
    --no-setup) setup=0; shift ;;
    --uninstall) uninstall=1; shift ;;
    --force) force=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) usage >&2; die "unrecognised argument: $1" ;;
  esac
done

[ -n "$prefix" ] || die "no prefix: pass --prefix DIR, or set HOME"
[ "$force" -eq 0 ] || [ "$uninstall" -eq 1 ] || die "--force goes with --uninstall"
case "$prefix" in
  /*) ;;
  *) prefix="$PWD/$prefix" ;;
esac
prefix="${prefix%/}"
[ -n "$prefix" ] || die "refusing to use / as the prefix"

# The harness configs vahta setup writes to (see crates/harness/harnesses).
config_files() {
  printf '%s\n' \
    "${HOME:-}/.claude/settings.json" \
    "${CODEX_HOME:+$CODEX_HOME/hooks.json}" \
    "${HOME:-}/.codex/hooks.json" \
    "${HOME:-}/.cursor/hooks.json"
}

# Print the configs that still name the hook in this prefix.
configs_pointing_here() {
  local f
  while IFS= read -r f; do
    [ -n "$f" ] && [ -f "$f" ] || continue
    if grep -qF -- "$prefix/vahta-hook" "$f" 2>/dev/null; then
      printf '%s\n' "$f"
    fi
  done < <(config_files)
}

if [ "$uninstall" -eq 1 ]; then
  pointing="$(configs_pointing_here)"
  if [ -n "$pointing" ] && [ "$force" -eq 0 ]; then
    {
      echo "install-local: error: harness configs still point into $prefix:"
      printf '%s\n' "$pointing" | sed 's/^/  /'
      echo "Removing the hook now would leave those harnesses running a missing hook."
      echo "Run \`$prefix/vahta setup --all --uninstall\` first, or pass --force."
    } >&2
    exit 1
  fi
  for name in vahta vh vahta-hook; do
    if [ -e "$prefix/$name" ] || [ -L "$prefix/$name" ]; then
      rm -f -- "$prefix/$name"
      echo "removed $prefix/$name"
    else
      echo "not installed: $prefix/$name"
    fi
  done
  exit 0
fi

command -v cargo >/dev/null 2>&1 || die "cargo not found; install a Rust toolchain first"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

echo "building vahta, vh and vahta-hook (release)..."
cargo build --release --locked -p vahta-cli -p vahta-hook

target_dir="$(cargo metadata --format-version 1 --no-deps --locked 2>/dev/null \
  | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')"
target_dir="${target_dir:-$repo/target}"
for name in vahta vh vahta-hook; do
  [ -x "$target_dir/release/$name" ] || die "build did not produce $target_dir/release/$name"
done

mkdir -p -- "$prefix"

# Copy next to the target, then rename over it: rename is atomic, and unlike
# writing into a running binary it cannot fail with "text file busy".
install_one() {
  local name="$1" tmp
  tmp="$(mktemp "$prefix/.$name.XXXXXX")"
  # shellcheck disable=SC2064
  trap "rm -f -- '$tmp'" EXIT
  cp -- "$target_dir/release/$name" "$tmp"
  chmod 755 "$tmp"
  mv -f -- "$tmp" "$prefix/$name"
  trap - EXIT
  echo "installed $prefix/$name"
}

# The hook first: a vahta that is newer than its hook is the worse way round.
install_one vahta-hook
install_one vahta
install_one vh

echo
echo "smoke checks..."
"$prefix/vahta" --version || die "$prefix/vahta --version failed"
"$prefix/vh" --version >/dev/null || die "$prefix/vh --version failed"
hook_out="$(echo '{}' | "$prefix/vahta-hook" --harness claude --event before_tool)" \
  || die "vahta-hook exited non-zero on an empty event"
[ -z "$hook_out" ] || die "vahta-hook printed something on an empty event: $hook_out"
echo "vahta-hook: ok (exit 0, empty stdout)"

case ":${PATH:-}:" in
  *":$prefix:"*) ;;
  *)
    echo
    echo "warning: $prefix is not on your PATH. Add this to your shell profile:"
    echo "  export PATH=\"$prefix:\$PATH\""
    ;;
esac

if [ "$setup" -eq 1 ]; then
  echo
  "$prefix/vahta" setup --refresh
  echo
  "$prefix/vahta" setup
else
  echo
  echo "skipped setup (--no-setup). Run \`$prefix/vahta setup --refresh\` to repoint existing harnesses."
fi
