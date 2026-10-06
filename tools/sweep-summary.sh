#!/usr/bin/env bash
# Summarise defuse-sweep runs captured from send.py output.
#
#   ./tools/sweep-summary.sh logs/*.txt
#   ... | python3 tools/sweep-summary.py -          (read stdin)
#
# One line per run: where it stopped, and the sweep tally. The point is to see
# whether the wedge lands at the same id every time or wanders -- a wandering
# fault and a fixed one have different causes, and we cannot tell them apart
# from a single run.

set -uo pipefail

emit() { python3 "$(dirname "$0")/sweep_summary.py" "$@"; }

if [ "$#" -gt 0 ]; then
  for f in "$@"; do emit "$f"; done
else
  emit -
fi