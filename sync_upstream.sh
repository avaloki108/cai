#!/bin/bash

# CAI Upstream Sync Script
# This script safely pulls updates from the original aliasrobotics/cai repository
# while keeping your personal changes completely separate and never pushing to upstream.
# 
# Author: Your AI Assistant
# Created: November 4, 2025
# 
# SAFETY GUARANTEE: This script will NEVER push your changes to the upstream repository.
# It only pulls FROM upstream, never pushes TO upstream.

set -e  # Exit on any error

# Colors for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script configuration
UPSTREAM_REPO="https://github.com/aliasrobotics/cai.git"
UPSTREAM_REMOTE="upstream"
BACKUP_PREFIX="backup-before-sync"
LOG_FILE="sync_upstream.log"

echo -e "${CYAN}🚀 CAI Upstream Sync Script${NC}"
echo -e "${CYAN}============================${NC}"
echo -e "${YELLOW}📅 $(date)${NC}"
echo ""

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
    echo -e "$1"
}

# Function to create separator
separator() {
    echo -e "${BLUE}----------------------------------------${NC}"
}

# Check if we're in the correct directory
if [[ ! -f "pyproject.toml" ]] || [[ ! -d "src/cai" ]]; then
    log_message "${RED}❌ Error: This doesn't appear to be the CAI repository root${NC}"
    log_message "${RED}   Please run this script from the CAI repository root directory${NC}"
    exit 1
fi

log_message "${GREEN}✅ Confirmed: Running in CAI repository${NC}"

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    log_message "${RED}❌ Error: Not in a git repository${NC}"
    exit 1
fi

# Get current branch
CURRENT_BRANCH=$(git branch --show-current)
log_message "${BLUE}📍 Current branch: ${CURRENT_BRANCH}${NC}"

# Check if we have any uncommitted changes (excluding the log file)
git add "$LOG_FILE" 2>/dev/null || true  # Add log file to avoid conflicts
if ! git diff-index --quiet HEAD --; then
    # Check if there are changes other than the log file
    UNCOMMITTED_FILES=$(git status --porcelain | grep -v "sync_upstream.log" | wc -l)
    if [[ "$UNCOMMITTED_FILES" -gt 0 ]]; then
        log_message "${YELLOW}⚠️  Warning: You have uncommitted changes!${NC}"
        echo ""
        log_message "${YELLOW}Uncommitted files:${NC}"
        git status --porcelain | grep -v "sync_upstream.log" | head -10
        if [[ $(git status --porcelain | grep -v "sync_upstream.log" | wc -l) -gt 10 ]]; then
            echo "... and $(($(git status --porcelain | grep -v "sync_upstream.log" | wc -l) - 10)) more files"
        fi
        echo ""
        read -p "Do you want to stash these changes temporarily? (y/N): " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            STASH_MESSAGE="Auto-stash before upstream sync $(date '+%Y-%m-%d %H:%M:%S')"
            # Stash everything except the log file
            git stash push -m "$STASH_MESSAGE" -- $(git diff --name-only | grep -v "sync_upstream.log")
            log_message "${GREEN}✅ Changes stashed with message: $STASH_MESSAGE${NC}"
            STASHED=true
        else
            log_message "${RED}❌ Please commit or stash your changes first, then run this script again${NC}"
            exit 1
        fi
    fi
fi

separator

# Check if upstream remote exists and is correct
log_message "${BLUE}🔍 Checking upstream remote configuration...${NC}"
if git remote get-url "$UPSTREAM_REMOTE" > /dev/null 2>&1; then
    CURRENT_UPSTREAM=$(git remote get-url "$UPSTREAM_REMOTE")
    if [[ "$CURRENT_UPSTREAM" != "$UPSTREAM_REPO" ]]; then
        log_message "${YELLOW}⚠️  Upstream remote exists but points to: $CURRENT_UPSTREAM${NC}"
        log_message "${YELLOW}   Expected: $UPSTREAM_REPO${NC}"
        read -p "Do you want to update the upstream remote URL? (y/N): " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            git remote set-url "$UPSTREAM_REMOTE" "$UPSTREAM_REPO"
            log_message "${GREEN}✅ Updated upstream remote URL${NC}"
        else
            log_message "${RED}❌ Keeping existing upstream remote. This may cause issues.${NC}"
        fi
    else
        log_message "${GREEN}✅ Upstream remote correctly configured${NC}"
    fi
else
    log_message "${YELLOW}⚠️  Upstream remote not found. Adding it now...${NC}"
    git remote add "$UPSTREAM_REMOTE" "$UPSTREAM_REPO"
    log_message "${GREEN}✅ Added upstream remote: $UPSTREAM_REPO${NC}"
fi

# Double-check that we can't accidentally push to upstream
log_message "${BLUE}🔒 Ensuring upstream is fetch-only (safety measure)...${NC}"
git remote set-url --push "$UPSTREAM_REMOTE" "DISABLED-NO-PUSH"
log_message "${GREEN}✅ Upstream remote set to fetch-only (cannot accidentally push)${NC}"

separator

# Fetch latest changes from upstream
log_message "${BLUE}📡 Fetching latest changes from upstream...${NC}"
if git fetch "$UPSTREAM_REMOTE"; then
    log_message "${GREEN}✅ Successfully fetched from upstream${NC}"
else
    log_message "${RED}❌ Failed to fetch from upstream${NC}"
    exit 1
fi

# Check for updates
log_message "${BLUE}📊 Checking for available updates...${NC}"
UPSTREAM_COMMITS=$(git rev-list HEAD.."$UPSTREAM_REMOTE"/main --count 2>/dev/null || echo "0")

if [[ "$UPSTREAM_COMMITS" -eq 0 ]]; then
    log_message "${GREEN}✅ You're already up to date with upstream!${NC}"
    
    # Commit the log file if it has changes
    git add "$LOG_FILE" 2>/dev/null || true
    git commit -m "Update sync log" 2>/dev/null || true
    
    # Restore stashed changes if any
    if [[ "$STASHED" == "true" ]]; then
        log_message "${BLUE}📦 Restoring your stashed changes...${NC}"
        if git stash pop; then
            log_message "${GREEN}✅ Your changes have been restored${NC}"
        else
            log_message "${YELLOW}⚠️  Some conflicts while restoring. Please check manually.${NC}"
        fi
    fi
    
    log_message "${CYAN}🎉 No action needed - everything is current!${NC}"
    exit 0
fi

log_message "${PURPLE}📦 Found $UPSTREAM_COMMITS new commits from upstream${NC}"

separator

# Show what we're about to merge
log_message "${BLUE}🔍 Here are the new commits from upstream:${NC}"
echo ""
git log --oneline --graph --decorate HEAD.."$UPSTREAM_REMOTE"/main | head -20
if [[ $(git rev-list HEAD.."$UPSTREAM_REMOTE"/main --count) -gt 20 ]]; then
    echo "... and $(($(git rev-list HEAD.."$UPSTREAM_REMOTE"/main --count) - 20)) more commits"
fi
echo ""

# Show file changes summary
log_message "${BLUE}📋 Summary of files that will be changed:${NC}"
git diff --name-status HEAD.."$UPSTREAM_REMOTE"/main | head -15
if [[ $(git diff --name-status HEAD.."$UPSTREAM_REMOTE"/main | wc -l) -gt 15 ]]; then
    echo "... and $(($(git diff --name-status HEAD.."$UPSTREAM_REMOTE"/main | wc -l) - 15)) more files"
fi

separator

# Confirmation
echo -e "${YELLOW}⚠️  IMPORTANT SAFETY REMINDER:${NC}"
echo -e "${YELLOW}   - This will merge upstream changes into your local branch${NC}"
echo -e "${YELLOW}   - Your personal changes will be preserved${NC}"
echo -e "${YELLOW}   - A backup will be created automatically${NC}"
echo -e "${YELLOW}   - Your changes will NEVER be pushed to upstream${NC}"
echo ""
read -p "Do you want to proceed with the merge? (y/N): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_message "${RED}❌ Sync cancelled by user${NC}"
    
    # Commit the log file if it has changes
    git add "$LOG_FILE" 2>/dev/null || true
    git commit -m "Update sync log" 2>/dev/null || true
    
    # Restore stashed changes if any
    if [[ "$STASHED" == "true" ]]; then
        log_message "${BLUE}📦 Restoring your stashed changes...${NC}"
        git stash pop 2>/dev/null || log_message "${YELLOW}⚠️  Stash restore had some issues, but your changes are safe${NC}"
        log_message "${GREEN}✅ Your changes have been restored${NC}"
    fi
    
    exit 0
fi

separator

# Create a backup branch before merging
BACKUP_BRANCH="$BACKUP_PREFIX-$(date +%Y%m%d-%H%M%S)"
log_message "${BLUE}💾 Creating backup branch: $BACKUP_BRANCH${NC}"
git branch "$BACKUP_BRANCH"
log_message "${GREEN}✅ Backup created: $BACKUP_BRANCH${NC}"

# Record pre-merge state
PRE_MERGE_COMMIT=$(git rev-parse HEAD)
log_message "${BLUE}📝 Pre-merge commit: $PRE_MERGE_COMMIT${NC}"

separator

# Perform the merge
log_message "${BLUE}🔄 Merging upstream changes...${NC}"
MERGE_MESSAGE="Sync with upstream aliasrobotics/cai - $(date '+%Y-%m-%d %H:%M:%S')"

if git merge "$UPSTREAM_REMOTE"/main --no-edit -m "$MERGE_MESSAGE"; then
    log_message "${GREEN}✅ Successfully merged upstream changes!${NC}"
    
    # Record post-merge state
    POST_MERGE_COMMIT=$(git rev-parse HEAD)
    log_message "${BLUE}📝 Post-merge commit: $POST_MERGE_COMMIT${NC}"
    
    separator
    
    log_message "${CYAN}🎉 Sync completed successfully!${NC}"
    echo ""
    log_message "${GREEN}📊 Summary of what happened:${NC}"
    log_message "   📦 Merged $UPSTREAM_COMMITS commits from upstream"
    log_message "   💾 Created backup branch: $BACKUP_BRANCH"
    log_message "   🔒 Upstream remains fetch-only (safe from accidental pushes)"
    
    echo ""
    log_message "${BLUE}📋 Recent changes merged:${NC}"
    git log --oneline "$PRE_MERGE_COMMIT".."$POST_MERGE_COMMIT" | head -10
    
else
    log_message "${RED}⚠️  Merge conflicts detected!${NC}"
    echo ""
    log_message "${YELLOW}🛠️  To resolve conflicts:${NC}"
    log_message "   1. Edit the conflicted files shown above"
    log_message "   2. Remove conflict markers (<<<<<<< ======= >>>>>>>)"
    log_message "   3. Run: git add ."
    log_message "   4. Run: git commit"
    echo ""
    log_message "${BLUE}💾 Your original state is backed up in: $BACKUP_BRANCH${NC}"
    echo ""
    log_message "${YELLOW}🔧 If you want to abort and restore original state:${NC}"
    log_message "   git merge --abort"
    log_message "   git checkout $BACKUP_BRANCH"
    echo ""
    
    # Don't restore stash if there are conflicts - user needs to resolve first
    if [[ "$STASHED" == "true" ]]; then
        log_message "${YELLOW}⚠️  Your stashed changes are still in the stash${NC}"
        log_message "   After resolving conflicts, run: git stash pop"
    fi
    
    exit 1
fi

# Restore stashed changes if any
if [[ "$STASHED" == "true" ]]; then
    separator
    log_message "${BLUE}📦 Restoring your stashed changes...${NC}"
    # Commit the log file first to avoid conflicts
    git add "$LOG_FILE" 2>/dev/null || true
    git commit -m "Update sync log" 2>/dev/null || true
    
    if git stash pop; then
        log_message "${GREEN}✅ Your changes have been restored and merged${NC}"
    else
        log_message "${YELLOW}⚠️  Conflicts while restoring stashed changes${NC}"
        log_message "   Please resolve manually and commit"
    fi
fi

separator

# Final recommendations
log_message "${CYAN}🎯 Recommended next steps:${NC}"
log_message "   1. 🧪 Test your application to ensure everything works"
log_message "   2. 🚀 Push updates to your fork: git push origin $CURRENT_BRANCH"
log_message "   3. 🗑️  Clean up old backup branches when confident"
echo ""
log_message "${BLUE}🔧 Emergency rollback (if needed):${NC}"
log_message "   git reset --hard $BACKUP_BRANCH"
echo ""
log_message "${GREEN}✅ Sync completed! Your repo now has all upstream updates.${NC}"
log_message "${GREEN}🔒 Your personal changes are preserved and safe.${NC}"

# Show current status
separator
log_message "${BLUE}📊 Current repository status:${NC}"
git status --short | head -10
if [[ $(git status --short | wc -l) -gt 10 ]]; then
    echo "... and $(($(git status --short | wc -l) - 10)) more files"
fi

echo ""
log_message "${CYAN}📝 Full log saved to: $LOG_FILE${NC}"