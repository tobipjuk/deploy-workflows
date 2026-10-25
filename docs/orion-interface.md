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
   - **exactly one job** over all attempts:
     `GET /repos/{o}/{r}/actions/runs/{run_id}/jobs?filter=all` → `total_count == 1`
     (an extra job in the same run could replace the artifacts, see 4a; re-run plans are refused);
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
   role: mark handled, optionally send an info message without buttons.
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
| `bundle_sha256`, `bundle_artifact` | Hash and artifact name (`plan-bundle`) of the bundle |

## 4a. Plan attestation (Guardian F1)

**Why.** `plan.yml` lives in the project repo, which the box can write. A job it adds to the
same run (`needs: plan`, `actions: write`) can download `plan-bundle`, keep the genuine tfplan,
swap a Lambda zip, re-tar it, and re-upload `plan-bundle` and `plan-summary` with a matching
`bundle_sha256` and any diff text. The changes digest covers only addresses and actions, so it
wouldn't notice. Therefore tf-plan.yml, inside its own job, requests a GitHub OIDC token whose
**audience commits to the sha256 of the bundle and of `plan-summary.json`**. Only a job running
deploy-workflows' `tf-plan.yml@refs/heads/main` gets a token with that `job_workflow_ref`; a
box-added job's token carries the project's own workflow ref. The token is not an AWS
credential (its `aud` is not `sts.amazonaws.com`).

Artifact `plan-attestation` (zip, two members, each ≤ 64 KB; refuse anything else):

- `manifest.json`: canonical JSON (sorted keys, no whitespace, ASCII), exactly these fields:

  ```
  {"bundle_sha256":"<64 hex>","repo":"<owner>/<name>","run_attempt":<int>,"run_id":<int>,
   "schema":1,"sha":"<40 hex>","summary_sha256":"<64 hex>","type":"deploy-workflows-plan"}
  ```

  `bundle_sha256` = sha256 of `plan-bundle.tar`; `summary_sha256` = sha256 of the **exact bytes**
  of `plan-summary.json` (the whole file: changes, digest, diff, flags, everything shown).
- `token.jwt`: the GitHub Actions OIDC token (compact JWS).

**Audience format:** `deploy-workflows-plan:v1:` + lowercase hex sha256 of the manifest bytes
exactly as stored (they must already be canonical: re-serialise and compare bytes; any
difference = refuse).

**Verification (Orion and tf-apply do the same):**

1. JWT header `alg == "RS256"` (anything else, incl. `none`/`HS256`, = refuse); `kid` selects a
   key from GitHub's JWKS `https://token.actions.githubusercontent.com/.well-known/jwks`
   (`kty RSA`, ≥ 2048 bits); RSASSA-PKCS1-v1_5 SHA-256 signature valid.
2. Claims: `iss == "https://token.actions.githubusercontent.com"`;
   `aud ==` the audience above (string, or a one-element array);
   `job_workflow_ref == "tobipjuk/deploy-workflows/.github/workflows/tf-plan.yml@refs/heads/main"`;
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
manifest = {"bundle_sha256":"2a8a9d944458564abae006e269da069ea3903a114e98303372cbbefee254bfee","repo":"tobipjuk/starhuntercrew","run_attempt":1,"run_id":18234567890,"schema":1,"sha":"1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d","summary_sha256":"951100431a6f44c5e81ab15634792e3d0be522af39146ac015b94b882cff2945","type":"deploy-workflows-plan"}
aud      = deploy-workflows-plan:v1:395d78925501c5e205e585f88defebda827878bf7e0d3418e9d298fc808d5af9
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
4. `Approve` → re-check section 3 **now** (still the newest successful plan run, one job, main
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
   (give up after 75 min and say so).
3. Report by editing the approval message (and a short new message so Telegram notifies):
   - success: download the `deploy-result` artifact (same zip rules; one member
     `deploy-result.json`: `status`, `applied` counts, `sha`, ids) → "Deployed starhuntercrew
     1a2b3c4: +2 ~5 -0 ±0, invalidations done, smoke ok" + run link;
   - failure: `GET /repos/{o}/{r}/actions/runs/{id}/jobs` → first job/step with
     `conclusion == "failure"` → "Deploy FAILED at <job> / <step>" + run link. A refusal by
     a gate (digest, destroy, plan run checks) shows up the same way.

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
