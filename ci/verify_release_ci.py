#!/usr/bin/env python3
import json
import os
import subprocess
import time


def api_pages(endpoint):
    return json.loads(subprocess.check_output(
        ["gh", "api", "--paginate", "--slurp", endpoint], text=True, timeout=30))


def ci_checks(repo, sha):
    workflows = [run for page in api_pages(
        f"repos/{repo}/actions/workflows/ci.yml/runs?head_sha={sha}&per_page=100")
        for run in page["workflow_runs"] if run["name"] == "CI"]
    suites = {run["check_suite_id"] for run in workflows}
    return [run for page in api_pages(
        f"repos/{repo}/commits/{sha}/check-runs?filter=latest&per_page=100")
        for run in page["check_runs"]
        if run["app"]["slug"] == "github-actions" and run["check_suite"]["id"] in suites]


def green(checks):
    return bool(checks) and all(
        run["status"] == "completed" and run["conclusion"] in ("success", "skipped")
        for run in checks)


def wait_for_ci(repo, sha):
    deadline = time.monotonic() + 20 * 60
    while True:
        checks = ci_checks(repo, sha)
        for run in checks:
            print(f'{run["name"]}: {run["status"]} / {run["conclusion"]}', flush=True)
        if green(checks):
            return
        if time.monotonic() >= deadline:
            raise SystemExit("CI did not pass within 20 minutes" if checks else
                             "No GitHub Actions CI check runs found within 20 minutes")
        time.sleep(min(20, max(0, deadline - time.monotonic())))


if __name__ == "__main__":
    wait_for_ci(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"])
