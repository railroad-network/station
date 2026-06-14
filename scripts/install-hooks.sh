#!/bin/sh
# Configure git to use the hooks checked into .githooks/.
set -e

repo_root=$(git rev-parse --show-toplevel)

chmod +x "$repo_root/.githooks/pre-commit"
git config core.hooksPath .githooks

echo "Installed git hooks: core.hooksPath = .githooks"
