#!/bin/bash
# CAI Repository Management Aliases
# Source this file in your ~/.zshrc: source /home/dok/tools/W3-AUDIT/cai/cai_aliases.sh

# Get the directory where this script is located
CAI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Quick update from upstream
alias cai-update="cd $CAI_DIR && ./update_from_upstream.sh"

# Check for available updates without merging
alias cai-check="cd $CAI_DIR && git fetch upstream && echo 'New commits available:' && git log --oneline HEAD..upstream/main || echo 'Already up to date!'"

# Show current status
alias cai-status="cd $CAI_DIR && echo '=== CAI Repository Status ===' && git status && echo && echo '=== Recent commits ===' && git log --oneline -5"

# Push your local changes to your fork
alias cai-push="cd $CAI_DIR && git push origin main"

# Quick commit of all changes
alias cai-commit="cd $CAI_DIR && git add . && git commit"

echo "✅ CAI aliases defined! You can now use:"
echo "   cai-update   - Update from upstream"
echo "   cai-check    - Check for available updates"
echo "   cai-status   - Show repository status"
echo "   cai-push     - Push to your fork"
echo "   cai-commit   - Quick commit all changes"