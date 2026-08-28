#!/bin/sh
# Point git at the version-controlled hooks in .githooks/.
#
# Run once per clone. Hooks are NOT cloned with a repo, so a fresh clone on
# another machine has no gate until this is run -- which is why CI runs the
# same checks server-side.

set -e
cd "$(git rev-parse --show-toplevel)"
chmod +x .githooks/* tools/*.py tools/*.sh 2>/dev/null || true
git config core.hooksPath .githooks
echo "hooks installed: core.hooksPath = $(git config core.hooksPath)"
echo
echo "Verifying the gate actually works:"
python3 tools/scrub.py --self-test | tail -3
