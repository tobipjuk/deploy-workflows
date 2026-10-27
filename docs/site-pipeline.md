# Site pipeline (site-plan.yml / site-apply.yml)

For projects that are a static site in S3 behind CloudFront, plus one Lambda's code and one
CloudFront Function (the "gate"), without Terraform. First user: lego-mindstorms (the Robot
Workshop). Design and Guardian findings: lego-mindstorms `docs/deploy-pipeline-design.md`
(revision 3, `d78d1d5`); this page documents what is built here and where it differs.

Same approval architecture as Terraform projects: `plan.yml` on every push to `main`, a
Telegram card from Orion, Tobi's 👍, Orion's App dispatches `deploy.yml`, AWS gives the deploy
role only to `site-apply.yml@main` dispatched by the App, attempt 1. What changes is that **no
project code runs**: the commit is data, and every "old" side of the card comes from AWS.

## Pieces

| File | What |
|---|---|
| `.github/workflows/site-plan.yml` | Reusable plan: checkout (`lfs: false`), trusted policy, plan role, `site_plan.py`, upload, nested `tf-attest.yml` |
| `.github/workflows/site-apply.yml` | Reusable apply: dispatch checks, `check_plan_run.py --kind site`, attestation, `site_apply.py --verify-only` before credentials, deploy role, `site_apply.py`, `deploy-result.json` |
| `scripts/site_policy.py` | Trusted policy and `deploy/site.json` validation; the fixed type, magic-byte and cache tables; key rules; the Lambda member shadowing check |
| `scripts/site_plan.py` | Reads the commit (`git ls-tree`/`cat-file`, raw objects), live state, LFS; builds plan, summary, bundle |
| `scripts/site_diff.py` | Pure diff logic: text rules, invisible/bidi escaping, S3 decisions, Lambda zip, ETags, change list |
| `scripts/site_bundle.py` | The content-addressed plan bundle |
| `scripts/site_apply.py` | The apply, in the design's order, silent |
| `scripts/site_aws.py` | The only AWS access: `aws` CLI with `--query` projections, errors reduced to the AWS error code |
| `scripts/lfs_fetch.py` | Strict LFS pointers, GitHub LFS batch API client, oid + size verification |
| `scripts/site_iam.py` | Renders the plan and deploy role policies from a site policy (drafts, nothing applied) |
| `docs/site-pipeline/lego-mindstorms-*-role.json` | The rendered drafts for review (from the test fixture policy: the distribution id is a placeholder) |

## Trusted policy `policy/site/<owner>/<repo>.json`

Chosen by `github.repository`; inputs may only agree with it. Onboarding is a reviewed PR here
(`mac/onboard.sh` will add it for `pipeline: site`). Example: `tests/fixtures/site/policy/tobipjuk/lego-mindstorms.json`.

| Field | Meaning |
|---|---|
| `schema`, `kind` | `1`, `"site"` |
| `repository`, `target` | the repo; the deploy target name (= Orion's registration) |
| `account_id`, `region`, `bucket` | the site bucket's account, region, name |
| `root_keys`, `prefixes` | SITE: the keys and prefixes the site may use. Nothing outside is ever written or deleted |
| `browser_code_sources` | repo prefixes types a browser runs may come from (`site/`) |
| `manifest` | `{bucket, key}` of `deployed-manifest.json` (a separate, versioned, private bucket) |
| `lambda` | `function_name`, `source_dir`, `members` (flat `*.py` allowlist, no stdlib/runtime names), `ignore` (globs of `.py` files in `source_dir` that aren't members, e.g. `test_*.py`) |
| `gate` | `function_name`, `source` (the `.js` in the repo), `tests`: 1-20 cases `{name, uri, method?, headers?, cookies?, expect}`; `expect` = `{"pass": true, "uri"?}` or `{"status": N, "location_prefix"?}` |
| `distribution_id` | for invalidations |
| `smoke` | `base_url` + up to 10 `{path, status, body_sha256_of_key?}` checks, without credentials |
| `max_objects`, `max_deletes` | default 20,000 and 20 |

## Project file `deploy/site.json` (untrusted, bounded)

```json
{"schema": 1,
 "mappings": [
   {"source": "site/index.html", "key": "index.html", "cache": "short"},
   {"source_dir": "building-instructions/pages/public", "prefix": "pages/", "cache": "immutable",
    "include": ["*.webp", "books.json"], "exclude": []}],
 "lambda_settings": {"runtime": "python3.13", "handler": "progress.handler", "memory_size": 256,
   "timeout": 10, "architectures": ["arm64"], "env_names": ["TABLE"], "layers": [], "vpc": false,
   "kms_key_arn": null, "package_type": "Zip"}}
```

Unknown fields, keys outside SITE, a key produced twice, a mapping that matches no file and
more than `max_objects` refuse the plan. `cache` is one of `no-cache`, `short`, `long`,
`immutable`, `private-short`, `private-day`, `private-immutable` (`site_policy.CACHE_CLASSES`).
`lambda_settings` is never applied: a difference from live makes the plan **not deployable**
("change it on the Mac first"). Content types come only from the extension table, checked on
both the key and the source (they must agree).

## Plan

`site_plan.py` exit codes: 0 ok, 1 refused, 3 no baseline on a push (the run fails, round 5 L3),
4 destructive without `allow_destroy`.

**Refused** (job fails, nothing offered): a text or code key whose source is an LFS pointer
(also near-pointers), a malformed pointer on a binary key, a symlink or submodule source, an
unknown or mismatched extension, an uppercase text extension, a browser type outside
`browser_code_sources`, failed magic bytes (plain-git bytes, verified LFS bytes, or the
adoption's unverified range read), non-UTF-8 text or control characters, an LFS object missing
from GitHub's store or not matching its oid, a `.py` file in the Lambda's `source_dir` that is
neither a member nor ignored, a member over 256 KB or not text, live Lambda code not matching
its `CodeSha256`, an invalid manifest.

**Not deployable** (card without buttons, no bundle): live settings ≠ `deploy/site.json`, a live
object outside SITE ("clean up on the Mac"), the gate's DEVELOPMENT config ≠ LIVE, a code diff
that doesn't fit (`diff_complete: false`), a summary too large, no deploy role.

**Adoption** (no manifest yet; only a hand-dispatched run): text keys adopt by live bytes
(sha256), binary keys by ETag (MD5 or 8 MiB multipart), LFS objects fetched and verified only
when a live key of the same size exists; other new LFS objects are existence-checked and
range-read for an unverified magic check (the apply verifies in full).

**Steady state**: the manifest is cross-checked against the live listing; any difference is
LIVE DRIFT (a drifted binary is re-uploaded; a live object in SITE that isn't in the manifest is
deleted; outside SITE it's not deployable). Text keys are always diffed against their live bytes.

## plan-summary.json (schema 1, `kind: "site"`)

The Terraform fields keep their meaning, so Orion's checks (section 4 of the interface) apply
unchanged: `changes` (`{address, actions}` sorted by address), `changes_digest` (same canonical
form), `counts`, `has_changes`, `destructive`, `deployable`, `blocked` (always `[]`),
`bundle_sha256`, `attention` (`{address, label, action, path, before, after}`). Addresses:
`s3:<key>`, `lambda:<function>`, `cloudfront-function:<function>`, `manifest:<key>`.
`diff` is `[]`; site extras:

| Field | Meaning |
|---|---|
| `diff_complete` | false = a code diff didn't fit; never deployable |
| `site.adoption` | baseline adoption |
| `site.not_deployable` | reasons (empty when deployable) |
| `site.prefixes` | `{prefix: {create, update, delete}}` ("(root)" for root keys) |
| `site.diffs` | `{address, file, kind: code\|data, text, added, removed, invisible}`: gate, Lambda, `pin.html`, `sw.js`, other code, then data. Unified diffs, invisible and bidi characters shown as `<U+XXXX>` |
| `site.data_diffs_truncated` | data (`.txt .ldr .mpd .py`) diffs dropped for size; code never is |
| `site.drift` | `{key, what}` |
| `site.settings_mismatch` | `{field, expected, live}` |
| `site.plan_sha256` | sha256 of the bundle's `plan.json`: binds summary and bundle |

NEEDS ATTENTION order (labels): Gate code, Gate DEVELOPMENT differs from LIVE, Lambda code,
PIN page, Service worker, New or renamed Lambda member, Non-text member in the live Lambda zip,
Delete of a root or code key, LIVE DRIFT, Settings mismatch, Invisible or bidi characters,
BASELINE ADOPTION. Up to 60 entries (drift over 20 keys is one entry).

## Bundle and manifest

`plan-bundle.tar`: `SOURCE`, `plan.json` (canonical JSON), `lambda.zip` and `gate.js` when they
change, `blobs/<sha256>` for every plain-git upload, `SHA256SUMS`. LFS objects travel as oids.
`plan.json` holds the operations with their preconditions, the full desired manifest, and the
pre-state: the whole listing (key → ETag), the manifest's ETag, the Lambda's `RevisionId` and
`CodeSha256`, the gate's LIVE/DEVELOPMENT ETags, config and code hashes, and the policy file's
sha256.

`deployed-manifest.json` (written only by the deploy role, `If-Match`/`If-None-Match: *`):
`{schema: 1, repository, bucket, commit, plan_run_id, written_at, objects: {key: {sha256, size,
etag, content_type, cache}}, lambda: {code_sha256, members: {name: sha256}}, gate: {live_sha256}}`.
After a failure it records only what was written; keys left half-way show as drift next time.

## Apply

Order and rules: `site_apply.py` docstring (design section 4). The apply re-derives the change
list from `plan.json` and compares the digest with the approved one, checks the policy file is
the one the plan saw, and re-validates every write against the policy and tables before
assuming the deploy role (`--verify-only`). Exit 0 applied, 1 refused before any write, 2
failed after a write (`partial=true`, `deploy-result.json` says "partially applied").

**Silent output** (round 4 M1, round 5 L4): the apply prints step names, counts and the gate
test cases by name with pass/FAIL. `site_aws.CliAws` captures all CLI output, asks only for
projected fields, and turns errors into `<operation>: <AWS error code>`. TestFunction's output is
evaluated in memory and dropped; its logs, error message and utilisation are never even
requested. Tests: `tests/test_site_apply.py` `GateTest`, `tests/test_site_policy.py` `CliAwsTest`.

## What is faked in the tests, and what needs real AWS

Faked (all of it, nothing here touches AWS or GitHub): S3, Lambda and CloudFront Functions
(`tests/site_fakes.FakeAws`, including conditional-write and revision semantics and a gate
simulator), the LFS server (a loopback HTTP server; the real `LfsClient` runs against it), the
`aws` binary (a script, for the CLI wrapper's argument and silence tests), and the run shapes
(synthetic site variants derived from the observed Terraform shapes).

Needs real AWS/GitHub, at build time (Tobi's Mac or the first pipeline runs):

| # | Check | How |
|---|---|---|
| B1 (M2b) | Do `UpdateFunction` / `TestFunction` on a function with a KeyValueStore association need `cloudfront:DescribeKeyValueStore`? | Policy simulator, then a test function with a KVS on the Mac. If yes: `site_iam.py --kvs-arn <arn>` (15 actions) |
| B2 | `s3:if-match` / `s3:if-none-match` condition keys make `DenyUnconditionalPut` deny a plain PutObject and allow both conditional forms | Policy simulator, both keys absent / each present |
| B3 | Conditional `DeleteObject` (`--if-match`) on a general-purpose bucket | `aws s3api delete-object --if-match` on a scratch bucket (if unsupported: drop the flag; the pre-state check still covers the window) |
| B4 | The aws CLI on `ubuntu-latest` accepts `--if-match`, `--if-none-match`, `--checksum-sha256` on `put-object` and returns `ChecksumSHA256` | first adoption run (`aws --version` in the log) |
| B5 | GITHUB_TOKEN (`contents: read`) works on the LFS batch API as `x-access-token` basic auth for a private repo | first adoption plan |
| B6 | The site bucket uses SSE-S3 (ETags are MD5s, no KMS needed; `kms:*` is denied) | `get-bucket-encryption` |
| B7 | The Lambda code `Location` host ends in `.amazonaws.com` | first plan |
| B8 | The real gate passes the three policy test cases in TestFunction (event shape `version 1.0`) | first apply (or a Mac `test-function` run with the same event JSON) |
| B9 | Plan role reads of text keys only: GetObject on a `.webp` is denied, on `.html` allowed | policy simulator |

## Where this differs from the design (revision 3)

1. **ListBucket on the manifest bucket** (both roles, prefix = the manifest key): without it S3
   returns 403 for a missing manifest, so "no baseline yet" couldn't be told from "access
   denied" (adoption plan and apply would both fail). Still 14 distinct actions (ListBucket is
   already in the list); the design's role tables need the extra resource.
2. **Plan role's NotAction deny** uses the plan role's own six actions, not the deploy role's
   14 (stricter; the design said "the same NotAction deny").
3. **File names:** the design's `site_plan.py` is split into `site_plan.py` (I/O) and
   `site_diff.py` (pure diff logic); `site_bundle.py`, `site_aws.py` and `site_iam.py` are extra.
4. **Exact-set run shape for Terraform too:** `check_plan_run.py` now requires exactly
   {`tf-plan.yml`, `tf-attest.yml`} for Terraform runs as well (before: both present, everything
   from deploy-workflows main). Stricter; all observed fixtures behave as before.
5. **The gate's source path is in the trusted policy**, not in `deploy/site.json`.
6. **A destructive plan without `allow_destroy`** writes no `plan-summary.json` (the job fails),
   like a refused plan; the step summary still shows the counts.
7. **Not built here:** the module's `pipeline = "site"` (roles, trust, the site bucket out of the
   object-read deny, `cloudfront-keyvaluestore:*` in the data guard), Orion's side, `mac/onboard.sh`
   site support, the lego callers and `infra/ci`.
