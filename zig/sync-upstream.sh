#!/usr/bin/env bash
# Rebase this fork onto the latest google/boringssl@main.
#
# This repo is a fork of google/boringssl: upstream files live at the repo
# root, and everything the fork adds lives under zig/ (plus the thin root
# build.zig, build.zig.zon and .github/workflows/ that must sit at the root).
# The fork's changes are kept as a single commit on top of upstream/main
# ("patch on top"), so `main` is always <upstream/main> + one Zoptia commit.
# Sync = `git rebase upstream/main`, followed by a force-push of main.
#
# Conflicts are unlikely but possible — most often if upstream renames a
# directory we list in build.zig.zon's `.paths`, or changes the
# gen/sources.json schema. Resolve, `git rebase --continue`, and keep the
# result a single commit (squash any fix-ups into it before pushing).

set -euo pipefail

UPSTREAM_URL="https://github.com/google/boringssl.git"
UPSTREAM_BRANCH="main"
REMOTE_NAME="upstream"

cd "$(git rev-parse --show-toplevel)"

# Add the upstream remote if it isn't there yet.
if ! git remote get-url "$REMOTE_NAME" >/dev/null 2>&1; then
    echo "Adding remote '$REMOTE_NAME' -> $UPSTREAM_URL"
    git remote add "$REMOTE_NAME" "$UPSTREAM_URL"
fi

echo "Fetching $REMOTE_NAME/$UPSTREAM_BRANCH..."
git fetch "$REMOTE_NAME" "$UPSTREAM_BRANCH"

echo "Rebasing onto $REMOTE_NAME/$UPSTREAM_BRANCH..."
git rebase "$REMOTE_NAME/$UPSTREAM_BRANCH"

# Upstream gates its fiat P-256 ADX SysV assembly on `__ELF__ || __APPLE__` in
# third_party/fiat/p256_64.h, so COFF builds never reference
# fiat_p256_adx_{mul,sqr}. If that gate ever loosens again (it was `__GNUC__`
# before upstream 28950bf42), win64 would reference a SysV-only body that is not
# assembled on PE/COFF — and, lacking a sysv_abi attribute, would call it with
# the wrong convention. Warn here so it is caught before a release, not by a
# downstream link error.
echo
gate_file="third_party/fiat/p256_64.h"
echo "Checking fiat P-256 ADX gate in $gate_file..."
if [ -f "$gate_file" ] && grep -q 'void fiat_p256_adx_mul' "$gate_file"; then
    # The `#if` line directly governing the declaration, plus its continuation.
    gate="$(sed -n '1,/void fiat_p256_adx_mul/p' "$gate_file" | grep -A1 '^#if' | tail -2)"
    if printf '%s' "$gate" | grep -q '__ELF__'; then
        echo "ok: fiat_p256_adx_* still gated on __ELF__/__APPLE__ (COFF unaffected)"
    else
        echo "WARNING: $gate_file no longer gates fiat_p256_adx_* on __ELF__:" >&2
        printf '%s\n' "$gate" >&2
        echo "  win64 (nasm path) may now reference SysV-only assembly. Verify the" >&2
        echo "  x86_64-windows-gnu build; see git history (src/win_fiat/) for the" >&2
        echo "  Win64->SysV shim that used to cover this." >&2
    fi
else
    echo "notice: fiat_p256_adx_* not declared in $gate_file; gate check skipped"
fi

# zig/build.zig drops crypto/fipsmodule/ec/p256_test.cc on x86_64 COFF because
# its guard (`__GNUC__ && __x86_64__`) is looser than the header's
# (`__ELF__ || __APPLE__`), so it references undeclared identifiers on mingw
# clang. Once upstream aligns the guard, the exclusion can be removed.
abi_test="crypto/fipsmodule/ec/p256_test.cc"
if [ ! -f "$abi_test" ]; then
    echo "notice: $abi_test is gone upstream; drop its exclusion in zig/build.zig"
elif grep -qE '__ELF__|__APPLE__|OPENSSL_WINDOWS' "$abi_test"; then
    echo "notice: $abi_test now gates on ELF/Apple/Windows; the COFF exclusion in"
    echo "        zig/build.zig (filterTestSources) is probably removable"
else
    echo "ok: $abi_test still uses the __GNUC__ guard; COFF exclusion in zig/build.zig still needed"
fi

# The FIPS service-indicator report labels services as covered / not covered
# from upstream source facts; re-derive them so the labels cannot go stale.
echo
if ! zig/check-indicator-coverage.sh; then
    echo
    echo "WARNING: indicator coverage facts moved upstream; update zig/indicator_report.cc" >&2
    echo "and zig/check-indicator-coverage.sh before the next FIPS release." >&2
fi

echo
echo "Done. Run 'zig build test' to verify the new upstream still builds, then"
echo "push with: git push --force-with-lease origin main"
