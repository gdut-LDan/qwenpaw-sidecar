#!/usr/bin/env bash
set -euo pipefail
bundle_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
runtime="${PYTHON_BIN:-python3.12}"
if ! command -v "$runtime" >/dev/null 2>&1; then
  runtime=python3
fi
"$runtime" -c 'import sys; assert sys.version_info >= (3,12), "需要 Python 3.12 或更新版本"'
exec "$runtime" "$bundle_dir/scripts/installer.py" upgrade "$@"
