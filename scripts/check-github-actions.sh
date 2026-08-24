#!/usr/bin/env bash
set -euo pipefail

actionlint_version=1.7.12
actionlint_sha256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
directory=$(mktemp -d)
trap 'rm -rf -- "$directory"' EXIT
archive="$directory/actionlint.tar.gz"

curl --fail --silent --show-error --location \
  --output "$archive" \
  "https://github.com/rhysd/actionlint/releases/download/v${actionlint_version}/actionlint_${actionlint_version}_linux_amd64.tar.gz"
echo "$actionlint_sha256  $archive" | sha256sum --check
tar --extract --gzip --file "$archive" --directory "$directory" actionlint
"$directory/actionlint"
