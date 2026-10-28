#!/usr/bin/env bash
# Fill a release tarball's directory (release.yml's Package step; CI runs
# it too, so a README change that breaks the tarball fails on the PR).
#
#   scripts/package.sh <ruxen binary> <dist dir> <git ref>
#
# README links to source-tree files listed in `online` become GitHub links
# at <ref>; every other relative link must resolve inside <dist>.

set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <ruxen binary> <dist dir> <git ref>" >&2
    exit 2
fi
bin=$(realpath "$1") dist=$(realpath -m "$2") ref=$3
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Linked from the README, not shipped: they need the source tree.
online=(DESIGN.md ROADMAP.md NGINX_TEST_PROGRESS.md CONTRIBUTING.md
    bench/ docs/ contrib/docker/Dockerfile)

mkdir -p "$dist/examples" "$dist/contrib/docker"
cp "$bin" "$dist/ruxen"
cp LICENSE NOTICE "$dist/"
cp examples/*.conf examples/mime.types "$dist/examples/"
cp -r contrib/systemd contrib/logrotate "$dist/contrib/"
cp contrib/docker/seccomp-io_uring.json "$dist/contrib/docker/"

base="https://github.com/gvozdetsky/ruxen/blob/$ref"
readme=$(<README.md)
for p in "${online[@]}"; do
    readme=${readme//"]($p"/"]($base/$p"}
done
printf '%s\n' "$readme" >"$dist/README.md"

bad=0
while read -r link; do
    path=${link%%#*}
    [[ -z $path || $path == *://* || $path == mailto:* ]] && continue
    if [[ ! -e $dist/$path ]]; then
        echo "README links $path, which is not in the tarball" >&2
        bad=1
    fi
done < <(grep -oE '\]\([^)[:space:]]+\)' "$dist/README.md" | sed -E 's/^\]\((.*)\)$/\1/')
exit $bad
