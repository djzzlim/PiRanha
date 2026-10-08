#!/bin/sh
set -e

echo "Uninstalling PiRanha..."

INSTALL_DIR="${PIRANHA_INSTALL_DIR:-$HOME/.local/bin}"
BIN_PATH="$INSTALL_DIR/piranha"

if [ -f "$BIN_PATH" ]; then
    echo "Removing binary at $BIN_PATH..."
    rm -f "$BIN_PATH"
else
    echo "Binary not found at $BIN_PATH."
fi

# Remove skills
echo "Removing installed skills..."
rm -rf "$HOME/.claude/skills/BugBountyFramework"
rm -rf "$HOME/.omp/agent/skills/piranha"
rm -rf "$HOME/.omp/skills/piranha"
rm -rf "$HOME/.omp/agent/skills/PiRanha"
rm -rf "$HOME/.omp/skills/PiRanha"
rm -rf "$HOME/.pi/agent/skills/piranha"
rm -rf "$HOME/.pi/skills/piranha"
rm -rf "$HOME/.pi/agent/skills/PiRanha"
rm -rf "$HOME/.pi/skills/PiRanha"

echo ""
echo "PiRanha has been uninstalled."
echo "Note: Session data and logs in ~/.claude/MEMORY/BugBounty were kept intact."
