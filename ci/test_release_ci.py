import unittest
from unittest.mock import patch

import verify_release_ci as release


def check(name="test", status="completed", conclusion="success", suite=1, app="github-actions"):
    return dict(name=name, status=status, conclusion=conclusion,
                check_suite={"id": suite}, app={"slug": app})


class ReleaseCiTests(unittest.TestCase):
    def test_only_the_ci_workflows_github_actions_checks_can_authorize_release(self):
        with patch.object(release, "api_pages", side_effect=[
            [{"workflow_runs": [{"name": "CI", "check_suite_id": 1}]}],
            [{"check_runs": [check(), check(suite=2), check(app="other")]}],
        ]):
            self.assertEqual(release.ci_checks("owner/repo", "sha"), [check()])

    def test_empty_pending_failed_or_cancelled_checks_do_not_pass(self):
        for checks in ([], [check(status="in_progress", conclusion=None)],
                       [check(conclusion="failure")], [check(conclusion="cancelled")],
                       [check(), check(conclusion="neutral")]):
            with self.subTest(checks=checks):
                self.assertFalse(release.green(checks))
        self.assertTrue(release.green([check(), check(conclusion="skipped")]))

    def test_pending_checks_are_polled_then_pass(self):
        with patch.object(release, "ci_checks", side_effect=[[], [check()]]), \
                patch.object(release.time, "monotonic", return_value=0), \
                patch.object(release.time, "sleep") as sleep:
            release.wait_for_ci("owner/repo", "sha")
        sleep.assert_called_once_with(20)

    def test_failed_checks_time_out_with_their_names_and_conclusions(self):
        with patch.object(release, "ci_checks", return_value=[check(conclusion="failure")]), \
                patch.object(release.time, "monotonic", side_effect=[0, 1200]), \
                patch("builtins.print") as output, self.assertRaises(SystemExit):
            release.wait_for_ci("owner/repo", "sha")
        output.assert_called_once_with("test: completed / failure", flush=True)
