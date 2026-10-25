#!/usr/bin/env python3
"""Check that the plan run a deploy was dispatched for is one that may be applied.

  check_plan_run.py --repo OWNER/REPO --run-id ID --expected-sha SHA
                    [--max-age-seconds 7200] [--plan-workflow .github/workflows/plan.yml]
                    [--reusable OWNER/deploy-workflows/.github/workflows/tf-plan.yml]

Needs GITHUB_TOKEN (actions: read) in the environment. The same rules are what Orion applies
before it offers a plan in Telegram (docs/orion-interface.md), so a plan Tobi could approve is
also one tf-apply accepts:

  - a run of the project's plan workflow, in this repository (not a fork), on branch main,
    event push or workflow_dispatch, completed with conclusion success
  - it used the reusable tf-plan.yml from deploy-workflows at refs/heads/main
  - it was made from the commit being deployed, which is main's head at dispatch time, so a
    newer commit on main supersedes it
  - it is the newest successful plan run on main
  - it started less than --max-age-seconds ago (2 h)
  - every referenced reusable workflow is from deploy-workflows at refs/heads/main
  - it has exactly one job over all attempts (no extra job that could swap artifacts)
"""
import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.parse
import urllib.request

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")


def parse_time(s):
    return dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))


def evaluate(run, latest_id, now, repo, expected_sha, plan_workflow, reusable, max_age, jobs=None):
    """jobs = the run's jobs from /jobs?filter=all (None = not checked)."""
    problems = []
    path = str(run.get("path") or "")
    if path != plan_workflow and not path.startswith(plan_workflow + "@"):
        problems.append(f"run is not of {plan_workflow} (path {path!r})")
    if (run.get("repository") or {}).get("full_name") != repo:
        problems.append("run belongs to another repository")
    if (run.get("head_repository") or {}).get("full_name") != repo:
        problems.append("run's head repository is not this repository (fork?)")
    if run.get("head_branch") != "main":
        problems.append(f"run is on branch {run.get('head_branch')!r}, not main")
    if run.get("event") not in ("push", "workflow_dispatch"):
        problems.append(f"run event is {run.get('event')!r}")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        problems.append(f"run is {run.get('status')}/{run.get('conclusion')}, not completed/success")
    if run.get("head_sha") != expected_sha:
        problems.append("plan was made from another commit than main's head (superseded)")
    refs = run.get("referenced_workflows") or []
    if not any(str(r.get("path", "")).startswith(reusable + "@") and r.get("ref") == "refs/heads/main"
               for r in refs):
        problems.append(f"run did not use {reusable}@refs/heads/main")
    # Every reusable workflow in the run must come from deploy-workflows' main: a box-written
    # plan.yml must not pull in anything else.
    anchor = reusable.split("/.github/")[0] + "/"
    for r in refs:
        if not (str(r.get("path", "")).startswith(anchor) and r.get("ref") == "refs/heads/main"):
            problems.append(f"run references a workflow outside {anchor}@refs/heads/main: {r.get('path')!r}")
    # Exactly one job (the tf-plan job), over all attempts: an extra job in the same run could
    # replace the run's artifacts (Guardian F1); a re-run adds jobs too.
    if jobs is not None:
        if len(jobs) != 1:
            problems.append(f"plan run has {len(jobs)} jobs (all attempts); exactly 1 (tf-plan) is required")
    if latest_id is None or int(latest_id) != int(run.get("id", -1)):
        problems.append("a newer successful plan run exists on main (superseded)")
    try:
        started = parse_time(run.get("run_started_at") or run.get("created_at"))
        age = (now - started).total_seconds()
        if age > max_age or age < -300:
            problems.append(f"plan is {int(age // 60)} min old; plans expire after {max_age // 60} min")
    except (TypeError, ValueError):
        problems.append("run has no usable start time")
    return problems


def get(path, token):
    req = urllib.request.Request(API + path, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--expected-sha", required=True)
    ap.add_argument("--max-age-seconds", type=int, default=7200)
    ap.add_argument("--plan-workflow", default=".github/workflows/plan.yml")
    ap.add_argument("--reusable", default="tobipjuk/deploy-workflows/.github/workflows/tf-plan.yml")
    ap.add_argument("--facts-out", help="write run_attempt, run_started_at, updated_at as JSON")
    args = ap.parse_args(argv)
    if not re.fullmatch(r"[1-9][0-9]{0,19}", args.run_id):
        print("::error::plan_run_id must be a run id (digits)", file=sys.stderr)
        return 1
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo) \
            or not re.fullmatch(r"[0-9a-f]{40}", args.expected_sha):
        print("::error::bad --repo or --expected-sha", file=sys.stderr)
        return 1
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("::error::GITHUB_TOKEN is not set", file=sys.stderr)
        return 1
    try:
        run = get(f"/repos/{args.repo}/actions/runs/{args.run_id}", token)
        wf = urllib.parse.quote(os.path.basename(args.plan_workflow))
        latest = get(f"/repos/{args.repo}/actions/workflows/{wf}/runs"
                     "?branch=main&status=success&per_page=1", token)
        jobs_doc = get(f"/repos/{args.repo}/actions/runs/{args.run_id}/jobs?filter=all&per_page=100", token)
    except Exception as e:  # noqa: BLE001 - any API failure refuses the deploy
        print(f"::error::cannot read the plan run: {e.__class__.__name__}", file=sys.stderr)
        return 1
    runs = latest.get("workflow_runs") or []
    latest_id = runs[0].get("id") if runs else None
    listed = jobs_doc.get("jobs") or []
    try:
        count = max(int(jobs_doc.get("total_count", len(listed))), len(listed))
    except (TypeError, ValueError):
        count = -1
    jobs = listed if count == len(listed) else [None] * max(count, 0)
    if count < 0:
        jobs = [None, None]  # unreadable count: fail closed
    problems = evaluate(run, latest_id, dt.datetime.now(dt.timezone.utc), args.repo,
                        args.expected_sha, args.plan_workflow, args.reusable, args.max_age_seconds, jobs)
    for p in problems:
        print(f"::error::Plan run {args.run_id}: {p}", file=sys.stderr)
    if problems:
        return 1
    if args.facts_out:
        with open(args.facts_out, "w", encoding="utf-8") as f:
            json.dump({"run_attempt": run.get("run_attempt"), "run_started_at": run.get("run_started_at"),
                       "updated_at": run.get("updated_at")}, f)
    print(f"plan run {args.run_id} ok (commit {args.expected_sha[:12]}, started {run.get('run_started_at')})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
