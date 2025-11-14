# CAI Upstream Sync

This directory contains scripts to safely sync your CAI repository with the upstream `aliasrobotics/cai` repository while preserving all your personal changes.

## 🚀 Quick Start

```bash
# Make sure you're in the CAI repository root
cd /home/dok/tools/cai

# Run the sync script
./sync_upstream.sh
```

## 📁 Files

- **`sync_upstream.sh`** - Main sync script (comprehensive, production-ready)
- **`update_from_upstream.sh`** - Simple update script (basic version)
- **`cai_aliases.sh`** - Convenient shell aliases
- **`UPSTREAM_SYNC_README.md`** - This documentation

## 🔒 Safety Guarantees

- ✅ **Never pushes your changes to upstream** - Upstream remote is set to fetch-only
- ✅ **Automatic backups** - Creates backup branches before every merge
- ✅ **Stash protection** - Safely handles uncommitted changes
- ✅ **Conflict handling** - Graceful handling of merge conflicts
- ✅ **Complete logging** - Full activity log in `sync_upstream.log`
- ✅ **Easy rollback** - Simple commands to undo if needed

## 🎯 What the Script Does

1. **Safety Checks**
   - Verifies you're in the correct repository
   - Checks for uncommitted changes
   - Offers to stash changes temporarily

2. **Remote Configuration**
   - Ensures upstream remote points to `aliasrobotics/cai`
   - Sets upstream to fetch-only (prevents accidental pushes)

3. **Update Process**
   - Fetches latest changes from upstream
   - Shows you exactly what will be merged
   - Creates automatic backup branch
   - Performs the merge safely

4. **Post-Merge**
   - Restores any stashed changes
   - Provides clear next steps
   - Saves complete log of activities

## 📊 Example Output

```
🚀 CAI Upstream Sync Script
============================
📅 Mon Nov  4 21:30:00 PST 2025

✅ Confirmed: Running in CAI repository
📍 Current branch: main
🔍 Checking upstream remote configuration...
✅ Upstream remote correctly configured
🔒 Ensuring upstream is fetch-only (safety measure)...
✅ Upstream remote set to fetch-only (cannot accidentally push)
📡 Fetching latest changes from upstream...
✅ Successfully fetched from upstream
📊 Checking for available updates...
📦 Found 5 new commits from upstream
```

## 🛠️ Advanced Usage

### Check for Updates (No Merge)
```bash
# Just check what's available
git fetch upstream
git log --oneline HEAD..upstream/main
```

### Manual Rollback
```bash
# If something goes wrong, rollback to backup
git reset --hard backup-before-sync-YYYYMMDD-HHMMSS
```

### Push Your Updates
```bash
# After successful sync, push to your fork
git push origin main
```

## ⚡ Quick Aliases

Source the aliases file for convenient shortcuts:

```bash
source ./cai_aliases.sh

# Then use:
cai-update    # Run the sync script
cai-check     # Check for available updates
cai-status    # Show repository status
cai-push      # Push to your fork
```

## 🔍 Troubleshooting

### Merge Conflicts
If you encounter conflicts:
1. Edit the conflicted files (look for `<<<<<<<`, `=======`, `>>>>>>>`)
2. Remove conflict markers
3. `git add .`
4. `git commit`

### Undo Everything
```bash
git merge --abort                    # Cancel ongoing merge
git checkout backup-before-sync-*   # Go to backup branch
```

### View Sync History
```bash
tail -50 sync_upstream.log  # See recent sync activity
```

## 📝 Notes

- The script creates timestamped backup branches before each sync
- All activity is logged to `sync_upstream.log`
- Your changes never leave your local repository
- The upstream remote is permanently set to fetch-only for safety

---

**Happy syncing! 🎉** Your personal changes will always be preserved while you get all the latest upstream improvements.