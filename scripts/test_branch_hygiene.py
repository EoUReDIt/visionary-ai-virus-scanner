import datetime as dt
import unittest

from branch_hygiene import classify, render

NOW = dt.datetime(2026, 11, 25, tzinfo=dt.timezone.utc)
RECENT = NOW - dt.timedelta(days=2)
OLD = NOW - dt.timedelta(days=90)


def c(ahead=1, last=RECENT, prs=(), based=(), sha="abc", behind=1):
    return classify("b", sha, "main", ahead, last, list(prs), list(based), NOW, behind_by=behind)


def pr(n, state="open", merged=False, sha="abc"):
    return {"number": n, "state": state, "merged": merged, "head_sha": sha}


class Classify(unittest.TestCase):
    def test_fully_merged_is_ready(self):
        self.assertEqual(c(ahead=0)[0], "READY")

    def test_fresh_empty_branch_is_not_ready(self):
        self.assertEqual(c(ahead=0, behind=0)[0], "KEEP")
        self.assertEqual(c(ahead=0, behind=0, prs=[pr(1, "closed", True)])[0], "READY")

    def test_squash_merged_pr_with_same_head_is_ready(self):
        self.assertEqual(c(ahead=5, prs=[pr(7, "closed", True, "abc")])[0], "READY")

    def test_commits_after_merge_are_kept(self):
        v, why = c(ahead=2, prs=[pr(7, "closed", True, "old")])
        self.assertEqual(v, "KEEP")
        self.assertIn("#7", why)

    def test_open_pr_keeps(self):
        self.assertEqual(c(ahead=0, prs=[pr(3)])[0], "KEEP")

    def test_stacked_pr_blocks_even_when_merged(self):
        v, why = c(ahead=0, based=[2, 3])
        self.assertEqual(v, "BLOCKED")
        self.assertIn("#2, #3", why)

    def test_closed_unmerged_needs_review(self):
        self.assertEqual(c(prs=[pr(4, "closed", False)])[0], "REVIEW")

    def test_stale_without_pr_needs_review_recent_is_kept(self):
        self.assertEqual(c(last=OLD)[0], "REVIEW")
        self.assertEqual(c(last=RECENT)[0], "KEEP")

    def test_render_lists_ready_branches_for_deletion(self):
        rows = [{"branch": "done", "verdict": "READY", "reason": "x", "ahead": 0, "behind": 3, "last_commit": "2026-11-01"},
                {"branch": "wip", "verdict": "KEEP", "reason": "y", "ahead": 2, "behind": 0, "last_commit": "2026-11-20"}]
        md = render("o/r", "main", rows, NOW)
        self.assertIn("git push origin --delete done", md)
        self.assertNotIn("--delete done wip", md)
        self.assertIn("1 READY to delete", md)

    def test_render_without_ready_has_no_delete_command(self):
        rows = [{"branch": "wip", "verdict": "KEEP", "reason": "y", "ahead": 2, "behind": 0, "last_commit": "2026-11-20"}]
        self.assertNotIn("git push origin --delete", render("o/r", "main", rows, NOW))


if __name__ == "__main__":
    unittest.main()
