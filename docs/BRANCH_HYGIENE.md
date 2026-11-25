# Branch hygiene tracker

A read-only workflow (`.github/workflows/branch-hygiene.yml`, script `scripts/branch_hygiene.py`) that tells a human
which branches are finished and safe to delete. **It never deletes anything.**

Where to look
- The open issue **Branch hygiene report** (updated in place every Monday, after every merged PR, and on demand).
- The run summary of the *branch-hygiene* workflow (Actions tab).
- Run it now: Actions -> branch-hygiene -> Run workflow.

Verdicts
| Verdict | Meaning | What to do |
|---|---|---|
| READY to delete | everything on the branch is already in the default branch (or its PR merged and nothing newer exists) | delete it; the report prints a ready-to-paste `git push origin --delete ...` |
| BLOCKED | an open PR is based on this branch (stacked PR) | retarget that PR to the default branch first |
| REVIEW | PR closed without merging, or unmerged commits and stale (30+ days) | decide: reopen, or delete if abandoned |
| KEEP | open PR, unmerged work, or commits added after its PR merged | leave it |

A brand-new branch identical to the default branch with no PR is reported as KEEP, not READY.

Local run (needs the GitHub CLI logged in):
```bash
GITHUB_REPOSITORY=owner/repo python3 scripts/branch_hygiene.py [--json] [--stale-days 30]
python3 -m unittest discover -s scripts -p "test_branch_hygiene.py"
```
Also enable *Settings -> General -> Automatically delete head branches* so merged PR branches go away by themselves.
