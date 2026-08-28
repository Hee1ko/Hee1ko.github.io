#!/bin/sh
# Local preview. Zero dependencies.
#
# Two known divergences from GitHub Pages, so you do not chase phantoms:
#   1. This does NOT serve your 404.html for missing paths -- it emits its own.
#   2. This does NOT redirect /resume -> /resume/ (Pages does). Test with the
#      trailing slash.
cd "$(git rev-parse --show-toplevel)"
echo "http://127.0.0.1:8000/  (ctrl-c to stop)"
exec python3 -m http.server 8000 --bind 127.0.0.1
