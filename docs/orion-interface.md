# Orion approver: interface contract

This is the exact behaviour Orion's **deploy approver** must implement. It turns a successful
`plan.yml` run into a Telegram approval for Tobi and, on his tap, dispatches `deploy.yml`.
AWS only issues deploy credentials to runs dispatched by this App (see `oidc-trust.md`), so the
approver plus Tobi's Telegram account **are** the production approval gate. Implement it as
plain deterministic code on the Orion host, not as something the LLM agent does.

Version: schema 1 (`plan-summary.json` `"schema": 1`). Times are UTC.

## 1. The GitHub App

| Setting | Value |
|---|---|
| Owner | `tobipjuk` (personal account), private App, installable only on this account |
| Name / slug | e.g. *Orion Approver* / `orion-approver`. The slug is what the trust pins: projects set repo variable `APPROVER_APP_SLUG` and their CI stack's `approver_app_slug` to it |
| Repository permissions | **Actions: Read and write** (list runs, download artifacts, `workflow_dispatch`), **Contents: Read-only** (branch head), **Metadata: Read-only** (mandatory). Nothing else. **No Contents write**, no Workflows, no Administration, no Secrets/Variables, no Environments |
| Webhook | Off (the approver polls) |
| Installation | "Only select repositories": exactly the registered project repos. Not deploy-workflows |
| Private key | Generated once, stored only on Orion's server (secret store / credential gateway, file mode 0600, never in git, never in an agent container) |

Token flow per call batch: JWT (RS256, `iss` = App ID, `iat` = now-60 s, `exp` ≤ now+9 min)
→ `POST /app/installations/{installation_id}/access_tokens` with body
`{"repositories": ["<repo name>"], "permissions": {"actions": "write", "contents": "read", "metadata": "read"}}`
→ installation token (1 h). Request a fresh token per repo; never log it. Headers on every
call: `Authorization: Bearer <token>`, `Accept: application/vnd.github+json`,
`X-GitHub-Api-Version: 2022-11-28`.

A run dispatched with this token has `github.actor` = `<slug>[bot]`; that is what the deploy
role's OIDC trust matches.

## 2. Registered repos

Config on the Orion server (not in any repo the box can write), e.g. `deploy-targets.json`:

```json
[
  {"target": "starhuntercrew", "repo": "tobipjuk/starhuntercrew",
   "plan_workflow": "plan.yml", "deploy_workflow": "deploy.yml", "installation_id": 12345678}
]
```

`target` must equal `plan-summary.json`'s `target`. See section 10 for registering a repo.

## 3. Discovering pending plans

Every 60 s, for each registered repo:

1. `GET /repos/{o}/{r}/actions/workflows/plan.yml/runs?branch=main&status=success&per_page=5`
2. Take `workflow_runs[0]` (newest). **Dedupe by run id**: keep a persistent set of handled run
   ids (offered, rejected, expired, superseded, no-changes); skip known ids.
3. Accept the run only if **all** hold (same rules as `scripts/check_plan_run.py`, which tf-apply
   enforces again):
   - `path` is `.github/workflows/plan.yml` (optionally with `@<ref>` suffix);
   - `repository.full_name` and `head_repository.full_name` both equal the registered repo;
   - `head_branch == "main"`, `event` is `push` or `workflow_dispatch`,
     `status == "completed"`, `conclusion == "success"`;
   - `referenced_workflows` contains an entry whose `path` starts with
     `tobipjuk/deploy-workflows/.github/workflows/tf-plan.yml@` and whose `ref` is
     `refs/heads/main`;
   - **every** `referenced_workflows` entry has a `path` starting with
     `tobipjuk/deploy-workflows/` and `ref == "refs/heads/main"`;
   - `referenced_workflows` contains `tobipjuk/deploy-workflows/.github/workflows/tf-plan.yml@…`
     **and** `…/tf-attest.yml@…`, both with `ref == "refs/heads/main"`;
   - **exactly two jobs** over all attempts, both `status == "completed"` and
     `conclusion == "success"`:
     `GET /repos/{o}/{r}/actions/runs/{run_id}/jobs?filter=all&per_page=100` → `total_count == 2`,
     one name ending in ` / terraform plan`, one ending in ` / attest / attest plan artifacts`
     (an extra job could replace artifacts or call tf-attest.yml on artifacts of its own, see 4a;
     names alone are spoofable, the count, success and references carry the check; re-run
     plans are refused);
   - **Exception, no plan bundle:** tf-plan runs its attest job only when it uploaded a plan
     bundle. When the plan has no changes, or the project has no deploy role, the run has
     exactly two jobs over all attempts: ` / terraform plan` completed/success, and the skipped
     nested call listed at caller level only (a name ending in ` / attest`, completed/skipped).
     Accept this shape only if the run has **no** `plan-bundle` and **no** `plan-attestation`
     artifact. Then go on with §4.1: no `plan-summary` = no changes (mark handled, no message);
     `plan-summary` = plan only (info message, no buttons). Any other skipped, failed or extra
     job, or a bundle or attestation next to a skipped attest job, is a refusal.
   - `head_sha` equals main's current head: `GET /repos/{o}/{r}/branches/main` → `commit.sha`;
   - age: `now - run_started_at < 2 h` (use the API's timestamp, not the summary's).
4. A newer accepted plan for the same repo **supersedes** any older pending one: edit the older
   Telegram message to "Superseded by run N" and remove its buttons.

Rate: 3 API calls per repo per minute is far inside the App's 5,000/h.

## 4. Reading the plan summary

1. `GET /repos/{o}/{r}/actions/runs/{run_id}/artifacts` → find `name == "plan-summary"`,
   `name == "plan-bundle"` and `name == "plan-attestation"`, all with `expired == false`
   (exactly one of each name; duplicates = refuse). No `plan-summary` = the plan had no
   changes: mark handled, no message. `plan-summary` but no `plan-bundle` = project has no deploy
   role: mark handled, optionally send an info message without buttons (the attest job is
   skipped in both cases, see §3).
2. `GET {archive_download_url}` (302 to a short-lived blob URL; follow it **without** forwarding
   the Authorization header). It is a zip: refuse if > 1 MB, if it holds anything other than one
   member `plan-summary.json`, or if that member is > 2 MB uncompressed.
3. **Verify the attestation (section 4a) before anything else**; the bytes of
   `plan-summary.json` it is checked against are exactly the bytes you then parse and show.
4. Parse JSON and validate. Refuse (log, no message) unless:
   - `schema == 1`, `repo` == registered repo, `target` == registered target,
     `run_id == run.id`, `sha == run.head_sha`;
   - `has_changes == true`, `deployable == true`, `blocked == []`;
   - `bundle_sha256` and `changes_digest` are 64 lowercase hex;
   - `changes_digest == sha256(canonical(changes))`, recomputed by Orion (below).
   - if `destructive == true`: `allow_destroy_requested == true` (otherwise tf-plan would have
     failed; treat a mismatch as tampering).

Canonical form of `changes`: the array **in the order given** (don't re-sort), each element
an object with keys `actions` then `address` (sorted keys), serialised with no whitespace
(`,` and `:` separators), non-ASCII characters escaped as `\uXXXX` with lowercase hex
(Python `json.dumps(changes, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`; in JS:
`JSON.stringify` of `{actions, address}` objects, then replace `/[\u0080-\uffff]/g` with
`\\u` + 4-digit lowercase hex). sha256 over the UTF-8 (= ASCII) bytes, lowercase hex.

Test vector:

```
changes = [{"actions":["create"],"address":"module.app.aws_s3_object.site[\"assets/js/ar.js\"]"},
           {"actions":["update"],"address":"module.app.aws_s3_object.site[\"é.txt\"]"}]
canonical = [{"actions":["create"],"address":"module.app.aws_s3_object.site[\"assets/js/ar.js\"]"},{"actions":["update"],"address":"module.app.aws_s3_object.site[\"é.txt\"]"}]
sha256 = 3b67c029e1b57856cef4f4db0542dd374b4548e25f944a35389a94546f2d384e
```

`plan-summary.json` fields (schema 1):

| Field | Meaning |
|---|---|
| `schema` | 1 |
| `repo`, `target`, `sha`, `ref`, `event`, `actor`, `run_id`, `run_attempt` | Where the plan came from |
| `created_at`, `expires_at` | Plan time and +2 h (display only; enforce from the API) |
| `commit_subject` | First line of the commit message, ≤ 120 printable chars. **Untrusted text** (anyone who can push writes it) |
| `counts` | `add`, `change`, `destroy`, `replace`, `forget`, `other`, `action_invocations`, `deferred` |
| `has_changes`, `destructive`, `deployable`, `allow_destroy_requested` | Booleans |
| `flags` | Strings explaining why a plan counts as destructive (action invocations, deferred changes) |
| `blocked` | Must be empty (provisioners, external programs, providers outside the allowlist) |
| `changes` | Every changed resource: `{address, actions}` sorted by address |
| `changes_digest` | sha256 of the canonical `changes` |
| `diff` | Up to 40 updated/replaced resources × 8 attributes: `{address, attrs: [{path, before, after}]}`; values ≤ 60 chars, sensitive or secret-named attributes are `(hidden)`, unknown ones `(known after apply)` |
| `diff_truncated` | Boolean |
| `attention`, `attention_truncated` | Up to 30 changes that redirect traffic or grant access: `{address, label, action, path, before, after}` (labels: API integration target, CloudFront origin, Lambda invoke permission, Lambda function URL auth, role trust policy, IAM policy document, managed policy attached, DNS record, SNS subscription, Lambda environment variable, S3 bucket configuration). Values are ≤ 100 chars; sensitive ones are `(hidden)`, policies/env `(changed, value not shown)`; `path`/`before`/`after` are null for bucket-config resources. **Show these first** in the message, under "NEEDS ATTENTION", before the change list. Optional field: absent in plans made before deploy-workflows adds it |
| `bundle_sha256`, `bundle_artifact` | Hash and artifact name (`plan-bundle`) of the bundle |

## 4a. Plan attestation (Guardian F1)

**Why.** `plan.yml` lives in the project repo, which the box can write. A job it adds to the
same run (`needs: plan`, `actions: write`) can download `plan-bundle`, keep the genuine tfplan,
swap a Lambda zip, re-tar it, and re-upload `plan-bundle` and `plan-summary` with a matching
`bundle_sha256` and any diff text. The changes digest covers only addresses and actions, so it
wouldn't notice. Therefore tf-plan.yml's second job, the nested **`tf-attest.yml`** (a separate
file, no checkout, no project code), downloads the two artifacts, re-checks them against the
plan job's hashes (job outputs), and requests a GitHub OIDC token whose **audience commits to
the sha256 of the bundle and of `plan-summary.json`**. Only that job carries
`job_workflow_ref = tobipjuk/deploy-workflows/.github/workflows/tf-attest.yml@refs/heads/main`:
a box-added job's token carries the project's own workflow ref, and the plan job's token carries
`tf-plan.yml` (the plan job runs project Terraform, sandboxed, and must not be able to attest).
A box-written `plan.yml` that calls `tf-attest.yml` directly is caught by the run-shape rules
of section 3 (exactly tf-plan's two jobs, both files referenced). GitHub environments can't be
used as the distinguishing claim: they aren't available for private repos on GitHub Free.
The token is not an AWS credential (its `aud` is not `sts.amazonaws.com`).

Artifact `plan-attestation` (zip, two members, each ≤ 64 KB; refuse anything else):

- `manifest.json`: canonical JSON (sorted keys, no whitespace, ASCII), exactly these fields:

  ```
  {"bundle_sha256":"<64 hex>","repo":"<owner>/<name>","run_attempt":<int>,"run_id":<int>,
   "schema":2,"sha":"<40 hex>","summary_sha256":"<64 hex>","type":"deploy-workflows-plan"}
  ```

  `bundle_sha256` = sha256 of `plan-bundle.tar`; `summary_sha256` = sha256 of the **exact bytes**
  of `plan-summary.json` (the whole file: changes, digest, diff, flags, everything shown).
- `token.jwt`: the GitHub Actions OIDC token (compact JWS).

**Audience format:** `deploy-workflows-plan:v2:` + lowercase hex sha256 of the manifest bytes
exactly as stored (they must already be canonical: re-serialise and compare bytes; any
difference = refuse).

**Verification (Orion and tf-apply do the same):**

1. JWT header `alg == "RS256"` (anything else, incl. `none`/`HS256`, = refuse); `kid` is a
   non-empty string and selects exactly one key from GitHub's JWKS
   `https://token.actions.githubusercontent.com/.well-known/jwks` (fetch over HTTPS, **refuse
   redirects**; `kty RSA`, ≥ 2048 bits); RSASSA-PKCS1-v1_5 SHA-256 signature valid.
2. Claims: `iss == "https://token.actions.githubusercontent.com"`;
   `aud ==` the audience above (string, or a one-element array);
   `job_workflow_ref == "tobipjuk/deploy-workflows/.github/workflows/tf-attest.yml@refs/heads/main"`
   (**not** tf-plan.yml);
   `repository ==` the registered repo; `run_id ==` the plan run id (string);
   `run_attempt ==` the run's `run_attempt` from the API (string); `sha ==` the run's `head_sha`;
   `ref == "refs/heads/main"`; `event_name` is `push` or `workflow_dispatch`;
   `iat` within `[run_started_at - 120 s, updated_at + 120 s]` of the run. **Ignore `exp`** (the
   token is a signature over the manifest; it expires minutes after the plan).
3. Manifest: fields exactly as above; `repo`, `run_id`, `run_attempt`, `sha` equal the run's.
4. `sha256(plan-summary.json bytes) == summary_sha256`; inside the summary,
   `bundle_sha256 == manifest.bundle_sha256` (Orion doesn't download the bundle; tf-apply
   additionally checks `sha256(plan-bundle.tar)`). The dispatched `bundle_sha256` and
   `changes_digest` must be the attested summary's values.

**Test vector:** `tests/fixtures/attestation-vector.json` (throwaway key, public half only):
`jwks`, `token_parts` (join with `.`), `manifest`, `aud`, `bundle_b64`, `summary`, `params`
(`repo`, `run_id`, `run_attempt`, `sha`, `not_before` = run_started_at, `not_after` = updated_at,
`bundle_sha256`, `summary_sha256`, `changes_digest`). Its values:

```
manifest = {"bundle_sha256":"2a8a9d944458564abae006e269da069ea3903a114e98303372cbbefee254bfee","repo":"tobipjuk/starhuntercrew","run_attempt":1,"run_id":18234567890,"schema":2,"sha":"1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d","summary_sha256":"951100431a6f44c5e81ab15634792e3d0be522af39146ac015b94b882cff2945","type":"deploy-workflows-plan"}
aud      = deploy-workflows-plan:v2:4d06d8f4086093a7d21ed8461141c2cdc4fa91577dd223e3697df5c02d534f6f
```

The token verifies against the vector's `jwks` with `params`; flipping one byte of the bundle,
the summary, the signature or any claim must fail. `tests/test_attest.py` is the reference
behaviour (`scripts/attest.py verify`).

## 5. The Telegram message

Send to Tobi's private chat only, plain text (no parse mode, so nothing in the summary can
inject markup or links), ≤ 4,096 characters (truncate the change list first, then the diff):

```
DEPLOY APPROVAL: starhuntercrew
Commit 1a2b3c4 "App: Sky AR (beta) ..."   [commit subject is untrusted text]
Plan run 18234567890, 10:42 UTC, expires 12:42 UTC
+2 add  ~5 change  -0 destroy  ±0 replace
Destructive: no

NEEDS ATTENTION (1):
! CloudFront origin (change) module.app.aws_cloudfront_distribution.this
    origin[0].domain_name: "shc-app.s3.eu-west-2.amazonaws.com" -> "attacker.example.net"

Changes (7):
+ module.app.aws_s3_object.site["assets/js/ar.js"]
+ module.app.aws_s3_object.site["assets/js/sky.js"]
~ module.app.aws_s3_object.site["assets/js/app.js"]
... and 4 more

Diff (redacted, truncated):
~ module.app.aws_s3_object.site["assets/js/app.js"]
    etag: "3f1c..." -> "9ab2..."

Digest 3b67c029...2d384e  Bundle 9f3e01aa...
https://github.com/tobipjuk/starhuntercrew/actions/runs/18234567890
https://github.com/tobipjuk/starhuntercrew/commit/<full sha>
```

Prefixes: `+` create, `~` update, `-` delete, `±` replace, `?` anything else. Show destroy and
replace lines first. Only the two GitHub URLs above are links, built by Orion from the repo and
ids (never taken from the summary).

Inline keyboard:

- `Approve` (non-destructive plans), or `Approve DESTROY` (destructive plans; a second
  "Confirm destroy" step is recommended), plus `Reject`.
- `callback_data` = `dep:<random 128-bit id, base64url>`; the id maps server-side to
  `{repo, run_id, bundle_sha256, changes_digest, allow_destroy, offered_at}`. Never put the
  values themselves in callback data. Each id is single-use.

## 6. Verifying the tap

On `callback_query`:

1. `callback_query.from.id` must equal Tobi's numeric Telegram user id (config value, not a
   username), and `callback_query.message.chat.id` must be his private chat. Anyone else:
   `answerCallbackQuery` with "Not allowed", log it, change nothing.
2. Look up the id: unknown, used, rejected, expired or superseded → answer "Expired" and do
   nothing.
3. `Reject` → mark handled, edit the message to "Rejected by Tobi at HH:MM", remove buttons.
4. `Approve` → re-check section 3 **now** (still the newest successful plan run, the two jobs, main
   head unchanged, `< 2 h`) and that `plan-bundle` and `plan-attestation` are still present and
   unexpired (same artifact ids as when offered). Any failure:
   edit to "Not deployed: <reason>" and stop. Then dispatch (section 7).

Audit log every offer, tap (user id, time), dispatch and result on the Orion server.

## 7. The dispatch

```
POST /repos/{o}/{r}/actions/workflows/deploy.yml/dispatches
{"ref": "main",
 "inputs": {"plan_run_id": "18234567890",
            "bundle_sha256": "<64 hex from plan-summary.json>",
            "changes_digest": "<64 hex, as recomputed>",
            "allow_destroy": "false"}}
```

`allow_destroy` is `"true"` only for an `Approve DESTROY` tap on a destructive plan. All
values are strings. Success is `204 No Content` (or `200` with the run's id when the API's
`return_run_details` option is available; use it if so). One deploy in flight per repo: refuse
a second approval until the first finishes.

## 8. Watching the deploy and reporting back

1. Find the run: from `return_run_details`, else poll
   `GET /repos/{o}/{r}/actions/workflows/deploy.yml/runs?event=workflow_dispatch&branch=main&per_page=5`
   for the newest run with `actor.login == "<slug>[bot]"` and `created_at >=` dispatch time
   minus 5 s (up to 2 min).
2. Poll `GET /repos/{o}/{r}/actions/runs/{id}` every 20 s until `status == "completed"`
   (the apply job times out after 45 min; give up after 60 min and say so).
3. Download the `deploy-result` artifact whenever it exists, whatever the run's conclusion
   (same zip rules; one member `deploy-result.json`, ≤ 64 KB). Schema 2:

   | Field | Meaning |
   |---|---|
   | `schema` | 2 |
   | `target`, `repo`, `sha`, `deploy_run_id`, `plan_run_id`, `bundle_sha256`, `changes_digest` | Identity; must match what was dispatched |
   | `applied` | Boolean: `terraform apply` of the saved plan succeeded |
   | `counts` | `add`, `change`, `destroy`, `replace` (ints or null) |
   | `checks` | Post-apply checks: `egress` (`ok`/`warning`/`skipped`), `invalidation` (`ok`/`failed`/`pending`/`skipped`), `smoke` (`ok`/`failed`/`skipped`) |
   | `status` | `deployed` / `deployed_with_warnings` / `failed` (below) |
   | `summary` | Short text, e.g. `applied, egress warning`, `applied, invalidation pending` |

4. Report by editing the approval message (and a short new message so Telegram notifies):
   - **✅ deployed**: `applied == true` and `status == "deployed"` (every check ok or skipped)
     → "✅ Deployed starhuntercrew 1a2b3c4: +2 ~5 -0 ±0, checks ok" + run link.
   - **⚠️ deployed, checks pending/failed**: `applied == true` and
     `status == "deployed_with_warnings"` → "⚠️ Deployed starhuntercrew 1a2b3c4, <summary>"
     (e.g. "applied, egress warning", "applied, invalidation pending", "applied, smoke failed")
     + run link. The change IS live; Tobi looks at the run. The job itself concludes success.
   - **anything else is a failure**: `applied == false`, `status == "failed"`, a missing or
     invalid result, or a run that didn't complete. `GET /repos/{o}/{r}/actions/runs/{id}/jobs`
     → first job/step with `conclusion == "failure"` → "❌ Deploy FAILED at <job> / <step>" + run
     link. A refusal by a gate (digest, destroy, plan run checks) shows up the same way.
   Validate `applied` against `status` (`deployed*` requires `applied == true`, `failed`
   requires `false`); a mismatch is a failure.

Never re-run a failed deploy run (AWS refuses attempt 2 anyway). A fix means a new commit,
a new plan and a new approval.

## 9. Expiry and supersession

- A plan can be approved for **2 h** after its `run_started_at`. After that the buttons are
  removed ("Expired, not deployed") and a tap answers "Expired". tf-apply enforces the same
  limit; the artifacts themselves live 1 day.
- A newer accepted plan run on the same repo supersedes the older one (section 3.4). A moved
  main head with no new plan yet also blocks the approval (section 6.4).
- On restart Orion reloads pending offers from its store and re-checks them before showing
  buttons as live.

## 10. Registering a repo

Prerequisites in the project repo (its specialist and Tobi do these):

1. The CI stack (module `github-oidc-roles`) applied with `create_deploy_role = true` and
   `approver_app_slug` = the App's slug.
2. OIDC sub template set (`oidc-trust.md`).
3. Repo variables: `AWS_ACCOUNT_ID`, `AWS_PLAN_ROLE_ARN`, `AWS_DEPLOY_ROLE_ARN`,
   `TF_STATE_BUCKET`, `APPROVER_APP_SLUG`, plus project-specific ones (e.g. `APP_HOST`).
4. `plan.yml` and `deploy.yml` calling the reusable workflows; one successful plan run.
5. A trusted egress/state policy `policy/egress/<owner>/<repo>.json` in deploy-workflows (a PR
   by Tobi). Without it every plan and deploy of the repo is refused.

On the Orion side:

1. GitHub → Settings → Applications → the App → Configure → add the repo to "Only select
   repositories". Note the installation id (`GET /app/installations` with the JWT).
2. Add the entry to `deploy-targets.json` (target, repo, workflows, installation id).
3. Check: with an installation token, `GET /repos/{o}/{r}/actions/workflows/plan.yml/runs?per_page=1`
   works, and the newest plan run's summary passes section 4.
4. Optional dry run: a harmless change (e.g. a comment in a site file) → offer arrives →
   Approve → run green → result message.

Removing a repo: delete the entry, remove the repo from the installation, and (in AWS) set
`create_deploy_role = false` or delete the deploy role.

## 11. Site plans (`kind: "site"`)

Projects without Terraform (first: lego-mindstorms) use `site-plan.yml` / `site-apply.yml`
(`docs/site-pipeline.md`). Everything above applies, with these differences.

**Registration.** A site target carries `"kind": "site"` in `deploy-targets.json`:

```json
{"target": "lego-mindstorms", "repo": "tobipjuk/lego-mindstorms", "kind": "site",
 "plan_workflow": "plan.yml", "deploy_workflow": "deploy.yml", "installation_id": 12345678}
```

An entry without `kind` is `terraform`. A plan is only offered when its run shape **and** its
summary's `kind` match the registration: a site run for a terraform target, or the other way
round, is refused (log, no message).

**Run shape (section 3) for site targets:**
- `referenced_workflows` is **exactly** the set {`tobipjuk/deploy-workflows/.github/workflows/site-plan.yml@…`,
  `…/tf-attest.yml@…`}, both `ref == "refs/heads/main"`, nothing else (for terraform targets:
  exactly {`tf-plan.yml`, `tf-attest.yml`});
- exactly two jobs over all attempts, both completed/success: one name ending in ` / site plan`,
  one ending in ` / attest / attest plan artifacts`;
- the no-bundle exception is the same (` / site plan` success + skipped ` / attest`, no bundle and
  no attestation artifact): a plan without changes, a not-deployable plan, or no deploy role.
- `scripts/check_plan_run.py --kind site` is the reference implementation (`tests/test_run_shapes.py`
  `SiteRunShapeTest`).

**Attestation (4a):** unchanged. The token comes from the same `tf-attest.yml@main`; it proves the
bytes, the kind comes from the run shape and the attested summary.

**Summary (section 4):** the same validation, plus `kind == "site"`, and **no buttons** unless
`deployable == true` **and** `diff_complete == true`. A not-deployable site plan arrives without a
bundle (info message with `site.not_deployable`, no buttons). Missing `kind` = `terraform`.

**The message (section 5) for site plans:**

```
DEPLOY APPROVAL: lego-mindstorms (site)
Commit 1a2b3c4 "Workshop: new robot page"   [untrusted text]
Plan run 18234567890, 10:42 UTC, expires 12:42 UTC
+3 add  ~2 change  -1 delete
Destructive: no

NEEDS ATTENTION (2):
! Gate code (update) cloudfront-function:ev3-workshop-site-pin  +4 -1 lines
! Service worker (update) s3:sw.js  +1 -1 lines

Changes by prefix: (root) ~2  pages/ +3  img/ -1
~ s3:index.html
~ s3:sw.js
+ s3:pages/abc123def0/p001.webp
... (first 15 paths; the rest in the attachment)

Full diffs: attached (lego-mindstorms-<run id>.txt)
Digest 3b67c029...2d384e  Bundle 9f3e01aa...
<run link> <commit link>
```

- NEEDS ATTENTION comes first, in the summary's order (`attention` is already ordered:
  invisible/bidi characters, gate, Lambda, `pin.html`, `sw.js`, Cache-Control or Content-Type,
  new Lambda members, non-text live members, data files without a diff, deletes of root/code
  keys, LIVE DRIFT, settings mismatch, Lambda env var names unreadable, non-ASCII letters in
  code, BASELINE ADOPTION). Show every entry: label, action, address, and the non-null of
  `path`/`before`/`after`. If Telegram's 4,096 characters force a cut, never drop an "Invisible
  or bidi characters" entry; cut from the end of the list instead.
- Then the per-prefix counts from `site.prefixes`, then the first 15 entries of `changes`
  (deletes first).
- **The attachment** (`sendDocument`, plain text, no parse mode; file name and caption built by
  Orion from the target and run id, never from the summary): the concatenated `site.diffs[].text`
  in the given order, each preceded by a line `=== <address> <file> (+<added> -<removed>)`,
  then the full `changes` list (one `<prefix> <address>` line each, prefixes as in section 5),
  then `site.drift` (`<key>: <what>`). Content only from the attested summary bytes. Diffs show
  invisible and bidi characters as `<U+XXXX>` already; Orion adds nothing.
- `Approve DESTROY` when `destructive == true` (more deletes than the policy's `max_deletes`), as
  for Terraform.
- **BASELINE ADOPTION** cards (first deploy, `site.adoption == true`) usually carry thousands of
  deletes and uploads: the attachment is the place to read them.

**Dispatch (7), watching (8):** unchanged; `deploy.yml` calls `site-apply.yml`. A failed site
apply after some writes reports `summary` "partially applied, see the run (the manifest records
what was written)" with `status: failed`.
