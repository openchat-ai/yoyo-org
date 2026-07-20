#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Push local commits to GitHub via `gh api` when direct git push is blocked.
  Tries normal git push first; falls back to API if that fails.

.PARAMETER Branch
  Branch to push (default: current branch).
.PARAMETER Force
  Force push (--force equivalent via API).
.PARAMETER Remote
  Remote name (default: origin).
#>

param(
  [string]$Branch = (git rev-parse --abbrev-ref HEAD 2>$null),
  [switch]$Force,
  [string]$Remote = "origin"
)

$ErrorActionPreference = "Continue"

# Resolve remote URL → owner/repo
$remoteUrl = git remote get-url $Remote 2>$null
if (-not $remoteUrl) { Write-Error "Remote '$Remote' not found"; exit 1 }

$ownerRepo = if ($remoteUrl -match 'github\.com[:/](.+/.+?)\.git') { $matches[1] }
             elseif ($remoteUrl -match 'github\.com[:/](.+/.+)') { $matches[1] }
             else { Write-Error "Can't parse owner/repo from $remoteUrl"; exit 1 }

Write-Host "Remote: $ownerRepo  Branch: $Branch"

# Step 1: try normal git push first
Write-Host "[1] Trying normal git push..." -NoNewline
$pushOut = & git push $Remote $Branch 2>$null
if ($LASTEXITCODE -eq 0) { Write-Host " OK"; return }

Write-Host " FAIL ($($LASTEXITCODE))"
Write-Host "[2] Falling back to gh api push..."

# Step 2: find local commits not on remote
$remoteRef = "refs/heads/$Branch"
$remoteSha = gh api "repos/$ownerRepo/git/$remoteRef" --jq '.object.sha' 2>$null
if (-not $remoteSha) { Write-Error "Can't get remote ref $remoteRef"; exit 1 }

$localCommits = git log "$Remote/$Branch..HEAD" --oneline --reverse 2>$null
if (-not $localCommits) { Write-Host "Nothing to push."; return }

$commits = @()
git log "$Remote/$Branch..HEAD" --format="%H" --reverse 2>$null | ForEach-Object { $commits += $_ }
Write-Host "  $($commits.Count) commit(s) to push"

# Step 3: Find changed files between remote and HEAD
$changedFiles = git diff "$Remote/$Branch..HEAD" --name-only 2>$null
Write-Host "  Changed files: $($changedFiles.Count)"

# Step 4: Create one combined commit via API (squash all local commits)
# First get the base tree
$baseCommit = gh api "repos/$ownerRepo/git/commits/$remoteSha" --jq '.tree.sha'
Write-Host "  Base tree: $baseCommit"

# Create blobs for all changed files
$treeEntries = @()
foreach ($file in $changedFiles) {
  if (-not (Test-Path $file)) {
    # File was deleted
    $treeEntries += @{path = $file; mode = "100644"; type = "blob"; sha = $null }
    continue
  }
  $content = Get-Content $file -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
  if (-not $content) { $content = "" }
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
  $b64 = [Convert]::ToBase64String($bytes)
  # Use temp file for large payloads to avoid CLI argument length limits
  $tmpJson = Join-Path ([System.IO.Path]::GetTempPath()) "gh-blob-$(Get-Random).json"
  @{content=$b64; encoding="base64"} | ConvertTo-Json -Compress | Set-Content $tmpJson -NoNewLine -Encoding ascii
  $blobSha = gh api "repos/$ownerRepo/git/blobs" --input $tmpJson --jq '.sha'
  Remove-Item $tmpJson -Force
  $treeEntries += @{path = $file.Replace('\', '/'); mode = "100644"; type = "blob"; sha = $blobSha }
  Write-Host "  Blob $file → $blobSha"
}

# Combine commit messages
$msgLines = @()
git log "$Remote/$Branch..HEAD" --format="%s" --reverse 2>$null | ForEach-Object { $msgLines += $_ }
$message = $msgLines -join "`n`n"

# Create tree
$treePayload = @{
  base_tree = $baseCommit
  tree = $treeEntries
} | ConvertTo-Json -Depth 10 -Compress
$newTree = echo $treePayload | gh api "repos/$ownerRepo/git/trees" --input - --jq '.sha'
Write-Host "  New tree: $newTree"

# Create commit
$commitJson = @{
  message = $message
  tree = $newTree
  parents = @($remoteSha)
} | ConvertTo-Json -Depth 10 -Compress
$newCommit = echo $commitJson | gh api "repos/$ownerRepo/git/commits" --input - --jq '.sha'
Write-Host "  Commit: $newCommit"

# Update ref
$patchFlag = if ($Force) { ",`"force=true`"" } else { "" }
$patchJson = "{`"sha`":`"$newCommit`"$patchFlag}"
echo $patchJson | gh api "repos/$ownerRepo/git/$remoteRef" --method PATCH --input - --jq '.ref'
Write-Host "  PUSHED: $remoteRef → $newCommit"

# Update local remote tracking branch
git fetch $Remote $Branch 2>&1 | Out-Null
