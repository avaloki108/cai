#!/bin/bash

# CAI Upstream Update Script
# This script safely pulls updates from the original aliasrobotics/cai repository
# while preserving your local changes and customizations.

set -e  # Exit on any error

echo "🚀 CAI Upstream Update Script"
echo "=============================="

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo "❌ Error: Not in a git repository"
    exit 1
fi

# Check if we have any uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo "⚠️  Warning: You have uncommitted changes. Please commit or stash them first."
    echo "Uncommitted files:"
    git status --porcelain
    exit 1
fi

# Check if upstream remote exists
if ! git remote get-url upstream > /dev/null 2>&1; then
    echo "❌ Error: 'upstream' remote not found. Adding it now..."
    git remote add upstream https://github.com/aliasrobotics/cai.git
    echo "✅ Added upstream remote"
fi

echo "📡 Fetching latest changes from upstream..."
git fetch upstream

echo "📊 Checking for updates..."
UPSTREAM_COMMITS=$(git rev-list HEAD..upstream/main --count)

if [ "$UPSTREAM_COMMITS" -eq 0 ]; then
    echo "✅ You're already up to date with upstream!"
    exit 0
fi

echo "📦 Found $UPSTREAM_COMMITS new commits from upstream"

# Show what we're about to merge
echo "🔍 Here are the new commits from upstream:"
git log --oneline HEAD..upstream/main

echo ""
read -p "Do you want to proceed with the merge? (y/N): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Update cancelled"
    exit 0
fi

# Create a backup branch before merging
BACKUP_BRANCH="backup-before-upstream-$(date +%Y%m%d-%H%M%S)"
echo "💾 Creating backup branch: $BACKUP_BRANCH"
git branch "$BACKUP_BRANCH"

echo "🔄 Merging upstream changes..."
if git merge upstream/main --no-edit; then
    echo "✅ Successfully merged upstream changes!"
    echo "🎉 Your repository is now up to date with upstream"
    echo "💾 Backup branch created: $BACKUP_BRANCH"
    echo ""
    echo "📝 Summary of changes:"
    git log --oneline "$BACKUP_BRANCH"..HEAD
else
    echo "⚠️  Merge conflicts detected!"
    echo "🛠️  Please resolve the conflicts manually, then run:"
    echo "   git add ."
    echo "   git commit"
    echo ""
    echo "💾 Your original state is backed up in branch: $BACKUP_BRANCH"
    echo "🔧 If you want to abort the merge and restore your original state:"
    echo "   git merge --abort"
    echo "   git checkout $BACKUP_BRANCH"
    exit 1
fi

echo ""
echo "🎯 Next steps:"
echo "1. Test your application to ensure everything works correctly"
echo "2. If you want to push the updates to your origin:"
echo "   git push origin main"
echo "3. If something goes wrong, you can restore from backup:"
echo "   git reset --hard $BACKUP_BRANCH"