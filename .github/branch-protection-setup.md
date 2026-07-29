# Branch protection setup — `main`

These settings must be applied **once** by a repository admin in
**Settings → Branches → Branch protection rules** (or via the newer
**Settings → Rules → Rulesets**).  
They cannot be enforced through a file in the repository — this document
is the authoritative reference so the configuration is auditable.

---

## Required rules for `main`

| Rule | Setting |
|---|---|
| **Require a pull request before merging** | ✅ Enabled |
| — Required approvals | `1` (minimum) |
| — Dismiss stale reviews on new commits | ✅ Enabled |
| — Require review from Code Owners | ✅ Enabled (enforces `CODEOWNERS`) |
| — Require conversation resolution before merging | ✅ Enabled |
| **Require status checks to pass** | ✅ Enabled |
| — Required checks | `Syntax & Compile`, `Tests (Python 3.11)` |
| — Require branches to be up to date | ✅ Enabled |
| **Do not allow bypassing the above settings** | ✅ Enabled |
| **Restrict who can push to matching branches** | ✅ Enabled — admins only |
| **Allow force pushes** | ❌ Disabled |
| **Allow deletions** | ❌ Disabled |

## Required merge strategy for `main`

Configure in **Settings → General → Pull Requests**:

| Setting | Value |
|---|---|
| Allow merge commits | ❌ Disabled |
| Allow squash merging | ✅ Enabled — default message: **Pull request title and description** |
| Allow rebase merging | ❌ Disabled |
| Automatically delete head branches | ✅ Enabled |

> Squash merging collapses all commits on a branch into a single commit on
> `main`, keeping the history linear and readable. The PR title becomes the
> commit subject and the PR body becomes the commit body — so filling out the
> PR template directly produces a useful `git log`.

---

## How to apply (GitHub UI)

1. Go to **Settings → Branches**.
2. Click **Add branch protection rule**.
3. Set **Branch name pattern** to `main`.
4. Tick every rule listed in the table above.
5. Click **Save changes**.

## How to apply (GitHub CLI)

```bash
# 1. Branch protection rule
gh api repos/{owner}/{repo}/branches/main/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["Syntax & Compile","Tests (Python 3.11)"]}' \
  --field enforce_admins=true \
  --field required_pull_request_reviews='{"dismiss_stale_reviews":true,"require_code_owner_reviews":true,"required_approving_review_count":1,"require_last_push_approval":false}' \
  --field required_conversation_resolution=true \
  --field restrictions=null

# 2. Merge strategy (squash-only, auto-delete branches)
gh api repos/{owner}/{repo} \
  --method PATCH \
  --field allow_merge_commit=false \
  --field allow_squash_merge=true \
  --field allow_rebase_merge=false \
  --field squash_merge_commit_title=PR_TITLE \
  --field squash_merge_commit_message=PR_BODY \
  --field delete_branch_on_merge=true
```

> **Note:** The GitHub CLI / REST API uses the older "branch protection" model.
> For the newer **Rulesets** model (recommended for organisations), use
> **Settings → Rules → Rulesets** and configure equivalent rules there.

---

## Why these rules?

- **No direct pushes to `main`** — every change arrives via a reviewed PR,
  giving the team visibility into what changed and why.
- **Code Owner review** — at least one maintainer listed in
  [`.github/CODEOWNERS`](CODEOWNERS) must approve before merge.
- **Status checks** — CI (lint + tests) must be green; broken code cannot
  slip in through a fast merge.
- **Stale review dismissal** — new commits after approval invalidate the
  previous approval, preventing approval-then-sneak-edit attacks.
- **Conversation resolution** — every review comment thread must be explicitly
  resolved before merge; nothing gets silently ignored.
- **Squash merging only** — one PR = one commit on `main`; history stays
  linear and `git bisect` / `git log` remain useful at scale.
