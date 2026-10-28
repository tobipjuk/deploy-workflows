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
| `allowed_cache` | one entry per root key and prefix: the cache classes `deploy/site.json` may choose there (e.g. `sw.js: ["no-cache"]`, `index.html: ["short", "no-cache"]`). Anything else refuses the plan |
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
`immutable`, `private-short`, `private-day`, `private-immutable` (`site_policy.CACHE_CLASSES`),
and must be in the policy's `allowed_cache` for that root key or prefix.
`lambda_settings` is never applied: a difference from live makes the plan **not deployable**
("change it on the Mac first"). Content types come only from the extension table, checked on
both the key and the source (they must agree).

**Env var names under the KMS deny** (Guardian on fff80e5, M1): Lambda decrypts the environment
on the caller's behalf, and the plan role is denied `kms:Decrypt` (`DenySecrets`), so
GetFunctionConfiguration returns `Environment = {"Error": {"ErrorCode": "AccessDeniedException"}}`
and no variables. `site_aws.py` projects that code (`env_error`); while it is set the names are
**not compared** (neither a mismatch nor a match), `site.settings_unverified` is `["env_names"]`
and NEEDS ATTENTION shows "Lambda env var names unreadable" ("env var names unreadable (KMS
denied: AccessDeniedException): not compared with deploy/site.json"). The other settings are still
compared. The plan role is deliberately **not** granted `kms:Decrypt` for this: it would hand it
the values, not just the names. Keep `env_names` in `deploy/site.json` accurate anyway (a role
that can read them compares them).

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

**Metadata** (Guardian on f944888, M1): an object is unchanged only if its bytes **and** its
`Content-Type` and `Cache-Control` are the desired ones. Text keys: from the same GetObject that
reads their bytes. Binary keys: in adoption a HEAD (8 in parallel) for every live key of the
right size; in steady state the manifest's values, trusted only while the live ETag **and**
LastModified equal the manifest's (an in-place `copy-object` keeps the ETag but not
LastModified, so it shows as LIVE DRIFT and the object is re-uploaded). A metadata-only
difference is an `update` (no diff text). NEEDS ATTENTION "Cache-Control or Content-Type" fires
for a root or code key whose Content-Type or Cache-Control changes, and for a new one created
with `long`, `immutable` or `private-immutable`.

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
| `site.settings_unverified` | settings that couldn't be read and weren't compared: `["env_names"]` under the plan role's KMS deny, else `[]` |
| `site.plan_sha256` | sha256 of the bundle's `plan.json`: binds summary and bundle |

NEEDS ATTENTION order (labels): Invisible or bidi characters, Gate code, Gate DEVELOPMENT
differs from LIVE, Lambda code, PIN page, Service worker, Cache-Control or Content-Type, New or
renamed Lambda member, Non-text member in the live Lambda zip, Delete of a root or code key,
LIVE DRIFT, Settings mismatch, Lambda env var names unreadable, Non-ASCII letters or combining marks in code, BASELINE ADOPTION.
Up to 60 entries (drift over 20 keys is one entry); invisible/bidi entries are never dropped by
the cap (Guardian L4).

## Bundle and manifest

`plan-bundle.tar`: `SOURCE`, `plan.json` (canonical JSON), `lambda.zip` and `gate.js` when they
change, `blobs/<sha256>` for every plain-git upload, `SHA256SUMS`. LFS objects travel as oids.
`plan.json` holds the operations with their preconditions, the full desired manifest, and the
pre-state: the whole listing (key → ETag), the manifest's ETag, the Lambda's `RevisionId` and
`CodeSha256`, the gate's LIVE/DEVELOPMENT ETags, config and code hashes, and the policy file's
sha256.

`deployed-manifest.json` (written only by the deploy role, `If-Match`/`If-None-Match: *`):
`{schema: 1, repository, bucket, commit, plan_run_id, written_at, objects: {key: {sha256, size,
etag, content_type, cache, last_modified}}, lambda: {code_sha256, members: {name: sha256}},
gate: {live_sha256}}`. `content_type` and `cache` are what is live (checked or written by the
pipeline); `last_modified` comes from a listing after the writes. The pre-state also records
every key's LastModified, and the apply refuses if one changed since the plan.
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
| B9 | Plan role: GetObject/HeadObject allowed on SITE keys, denied elsewhere in the bucket and on every write | policy simulator |
| B10 | Does an `s3:ListBucket` allow with the condition `s3:prefix = deployed-manifest.json` turn a missing manifest's 403 into a 404 (`NoSuchKey`)? It should (S3 checks ListBucket for the key being asked for), but S3 docs only promise it for unconditional ListBucket. **Fallback:** unconditional `s3:ListBucket` on the dedicated manifest bucket (it holds only the manifest) | `get-object` of a missing manifest as each role, before the adoption plan |

## Where this differs from the design (revision 3)

1. **ListBucket on the manifest bucket** (both roles, prefix = the manifest key): without it S3
   returns 403 for a missing manifest, so "no baseline yet" couldn't be told from "access
   denied" (adoption plan and apply would both fail). Still 14 distinct actions (ListBucket is
   already in the list); the design's role tables need the extra resource.
2. **Plan role's NotAction deny** uses the plan role's own six actions, not the deploy role's
   14 (stricter; the design said "the same NotAction deny").
   - **Plan role reads all of SITE, not only text keys** (Guardian on f944888, M1): HeadObject on
   binaries (adoption) is authorised as `s3:GetObject`. Nothing in SITE is secret (round 4 H1).
   - **Content-Type and Cache-Control are reconciled** (M1): the design compared bytes/ETags
   only, so a box-chosen `immutable` on `index.html` could ride along unseen. Now pinned per root
   key/prefix in the trusted policy (`allowed_cache`), compared with live, and shown.
   - **Invisible/bidi characters rank first** in NEEDS ATTENTION and are exempt from the cap (L4).
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

## Known limits (Guardian on f944888, info)

- **L5: TestFunction is not a boundary.** The gate tests run box-written code on the DEVELOPMENT
  stage before it goes live, and their inputs are in the policy (predictable): a malicious gate
  can recognise the test events and behave. The tests catch mistakes, not an attacker; the gate
  diff on the card (first in NEEDS ATTENTION) is what Tobi approves.
- **L6: the deploy role's API parameters are wider than the code uses.** IAM can't limit, for
  example, `UpdateFunctionCode` to a zip (vs. an S3 location or image), `PutObject` to the
  content types and cache classes of the tables, `CreateInvalidation` paths, or
  `UpdateFunction`'s config (runtime, key store association). The trusted code uses only the
  narrow forms; anyone holding the role's credentials could use the wide ones on the same
  resources. The role is only issued to `site-apply.yml@main` dispatched by the App, attempt 1.
- **L7: homoglyphs.** Added code lines with letters outside ASCII or combining marks get a NEEDS
  ATTENTION entry ("Non-ASCII letters or combining marks in code", count only). It is a hint:
  legitimate text (accents, emoji) triggers it too, and confusables inside ASCII (`l`/`1`) don't.
