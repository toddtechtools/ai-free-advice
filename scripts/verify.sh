#!/usr/bin/env bash
# Run from any directory; resolve the helper relative to this skill.
set -euo pipefail
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' 'HOLD: python3 is required; verification did not run.' >&2
  exit 3
fi
exec python3 "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/verify.py" "$@"
