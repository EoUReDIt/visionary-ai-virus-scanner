#!/usr/bin/env python3
"""Branch hygiene report: which branches are safe to delete, which are not, and why.

Read-only: it never deletes anything. It prints a Markdown report (for the
Actions summary and a tracking issue) with a copy-paste delete command for the
branches that are verifiably finished.

    GH_TOKEN=... GITHUB_REPOSITORY=owner/repo python3 scripts/branch_hygiene.py [--json] [--stale-days 30]

Verdicts, strongest first:
  BLOCKED  another open PR is based on this branch (a stacked PR): retarget it first
  KEEP     an open PR uses this branch, has unmerged commits, or got commits after its PR merged
  REVIEW   its PR was closed without merging, or it has unmerged commits and has gone stale
  READY    everything on it is already in the default branch: safe to delete
"""
import argparse
import datetime as dt
import json
import os
import subprocess
import sys

PRIORITY = {"READY": 0, "BLOCKED": 1, "REVIEW": 2, "KEEP": 3}


def classify(branch, sha, default, ahead_by, last_commit, prs, based_on_it, now, stale_days=30, behind_by=1):
    """Pure decision function.

    prs         pull requests whose head is this branch, newest first:
                dicts with number, state ('open'|'closed'), merged (bool), head_sha
    based_on_it open PR numbers whose *base* is this branch
    Returns (verdict, reason).
    """
    if based_on_it:
        nums = ", ".join(f"#{n}" for n in based_on_it)
        return "BLOCKED", f"open PR {nums} is based on this branch: retarget it to `{default}` first"
    open_prs = [p for p in prs if p["state"] == "open"]
    if open_prs:
        return "KEEP", f"open PR #{open_prs[0]['number']}"
    if ahead_by == 0 and behind_by == 0 and not prs:
        return "KEEP", f"identical to `{default}` with no PR: looks like a branch that was just created"
    if ahead_by == 0:
        return "READY", f"all commits are already in `{default}`"
    merged = [p for p in prs if p.get("merged")]
    if merged and merged[0]["head_sha"] == sha:
        return "READY", f"PR #{merged[0]['number']} was merged and the branch has no newer commits"
    if merged:
        return "KEEP", f"{ahead_by} commit(s) added after PR #{merged[0]['number']} merged"
    if prs:
        return "REVIEW", f"PR #{prs[0]['number']} was closed without merging ({ahead_by} unmerged commit(s)); delete if abandoned"
    age = (now - last_commit).days
    if age > stale_days:
        return "REVIEW", f"no PR, {ahead_by} unmerged commit(s), last commit {age} days ago"
    return "KEEP", f"{ahead_by} unmerged commit(s), no PR yet (last commit {age} day(s) ago)"


def gh(path, paginate=False):
    cmd = ["gh", "api"] + (["--paginate"] if paginate else []) + [path]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    if paginate:  # --paginate concatenates JSON arrays: "][" between pages
        out = out.replace("][", ",")
    return json.loads(out)


def parse_time(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def collect(repo, stale_days):
    info = gh(f"repos/{repo}")
    default = info["default_branch"]
    owner = repo.split("/")[0]
    branches = gh(f"repos/{repo}/branches?per_page=100", paginate=True)
    open_prs = gh(f"repos/{repo}/pulls?state=open&per_page=100", paginate=True)
    based = {}
    for p in open_prs:
        if p["base"]["repo"]["full_name"] == repo:
            based.setdefault(p["base"]["ref"], []).append(p["number"])
    now = dt.datetime.now(dt.timezone.utc)
    rows = []
    for b in branches:
        name = b["name"]
        if name == default or b.get("protected"):
            continue
        cmp_ = gh(f"repos/{repo}/compare/{default}...{name}")
        prs_raw = gh(f"repos/{repo}/pulls?state=all&head={owner}:{name}&per_page=10&sort=created&direction=desc")
        prs = [{"number": p["number"], "state": p["state"], "merged": bool(p.get("merged_at")),
                "head_sha": p["head"]["sha"]} for p in prs_raw]
        last = parse_time(cmp_["commits"][-1]["commit"]["committer"]["date"]) if cmp_["commits"] else \
            parse_time(gh(f"repos/{repo}/commits/{b['commit']['sha']}")["commit"]["committer"]["date"])
        verdict, reason = classify(name, b["commit"]["sha"], default, cmp_["ahead_by"], last, prs,
                                   based.get(name, []), now, stale_days, cmp_["behind_by"])
        rows.append({"branch": name, "verdict": verdict, "reason": reason, "ahead": cmp_["ahead_by"],
                     "behind": cmp_["behind_by"], "last_commit": last.date().isoformat()})
    rows.sort(key=lambda r: (PRIORITY[r["verdict"]], r["branch"]))
    return default, rows


ICON = {"READY": "READY to delete", "BLOCKED": "BLOCKED", "REVIEW": "REVIEW", "KEEP": "KEEP"}


def render(repo, default, rows, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    ready = [r["branch"] for r in rows if r["verdict"] == "READY"]
    out = [f"# Branch hygiene report", "",
           f"Repository `{repo}`, default branch `{default}`, generated {now:%Y-%m-%d %H:%M} UTC. "
           "This report only reads; nothing is deleted automatically.", ""]
    counts = {v: sum(1 for r in rows if r["verdict"] == v) for v in PRIORITY}
    out.append("**" + " · ".join(f"{counts[v]} {ICON[v]}" for v in PRIORITY) + "**")
    out.append("")
    if rows:
        out += ["| Branch | Verdict | Why | Ahead/behind | Last commit |", "|---|---|---|---|---|"]
        for r in rows:
            out.append(f"| `{r['branch']}` | {ICON[r['verdict']]} | {r['reason']} | +{r['ahead']} / -{r['behind']} | {r['last_commit']} |")
    else:
        out.append("No branches other than the default branch.")
    out.append("")
    if ready:
        out += ["## Ready to delete", "", "Run locally, or delete each in the GitHub branches page:", "", "```bash",
                "git push origin --delete " + " ".join(ready), "```", ""]
    out += ["Tip: enable *Settings -> General -> Automatically delete head branches* so merged PR branches disappear on their own.",
            "", "Verdicts: READY = fully merged, BLOCKED = a stacked PR still targets it, REVIEW = a human should decide, KEEP = still in use."]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--stale-days", type=int, default=30)
    a = ap.parse_args()
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        sys.exit("GITHUB_REPOSITORY is not set (owner/name)")
    default, rows = collect(repo, a.stale_days)
    print(json.dumps(rows, indent=2) if a.json else render(repo, default, rows))


if __name__ == "__main__":
    main()
