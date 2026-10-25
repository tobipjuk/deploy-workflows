#!/usr/bin/env bash
# LOCAL DEBUG ONLY (never in CI): run a project's real `terraform plan -lock=false` inside the
# sandbox + egress proxy in a throwaway container, with the trusted policy's host list, and list
# the hostnames the proxy allowed/refused (from a private file, shown only on this terminal).
# Use it to find hosts a policy is missing.
#
#   tests/sandbox/local-plan.sh REPO_DIR TF_DIR OWNER/REPO AWS_PROFILE [TF_BIN] [CODE_PROFILE]
#
# CODE_PROFILE: the profile name the Terraform code uses (e.g. shc); the credentials are written
# under it as well as [default], like the pipeline's aws_profile input.
#
# Credentials: short-lived ones exported from AWS_PROFILE (read-only role) into a private temp
# dir mounted into the container; deleted afterwards.
set -euo pipefail
[ "${GITHUB_ACTIONS:-}" != "true" ] || { echo "local debugging only" >&2; exit 1; }
repo=$(cd "${1:?REPO_DIR}" && pwd); tfdir=${2:?TF_DIR}; slug=${3:?OWNER/REPO}; profile=${4:?AWS_PROFILE}
tf=${5:-$(cd "$repo/$tfdir" && mise which terraform)}
code_profile=${6:-default}
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d "${XDG_CACHE_HOME:-$HOME/.cache}/tf-local-plan-XXXXXX")
chmod 700 "$work"
trap 'rm -rf "$work"' EXIT
pol="$root/policy/egress/$slug.json"
region=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["region"])' "$pol")
account=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["account_id"])' "$pol")
python3 -I "$root/scripts/egress_hosts.py" --policy-dir "$root/policy/egress" --repository "$slug" \
  --expect-region "$region" --expect-account "$account" --out "$work/hosts.txt" --github-output "$work/policy.env" >/dev/null
state_bucket=$(sed -n 's/^state_bucket=//p' "$work/policy.env")
state_region=$(sed -n 's/^state_region=//p' "$work/policy.env")
eval "$(aws configure export-credentials --profile "$profile" --format env-no-export)"
umask 077
: > "$work/credentials"; : > "$work/config"
for p in default "$code_profile"; do
  printf '[%s]\naws_access_key_id = %s\naws_secret_access_key = %s\naws_session_token = %s\n' \
    "$p" "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$AWS_SESSION_TOKEN" >> "$work/credentials"
  if [ "$p" = default ]; then printf '[default]\nregion = %s\n' "$region" >> "$work/config"
  else printf '[profile %s]\nregion = %s\n' "$p" "$region" >> "$work/config"; fi
  [ "$code_profile" != default ] || break
done
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
docker run --rm --cap-add NET_ADMIN -v "$root:/src:ro" -v "$repo:/repo:ro" -v "$tf:/opt/tf-src/terraform:ro" \
  -v "$work:/work" -e TFDIR="$tfdir" -e REGION="$region" -e STATE_BUCKET="$state_bucket" \
  -e STATE_REGION="$state_region" -e SANDBOX_FAIL_ON_REFUSED="${SANDBOX_FAIL_ON_REFUSED:-0}" ubuntu:24.04 bash -c '
set -e
apt-get update -qq >/dev/null && apt-get install -y -qq sudo iptables python3 curl ca-certificates >/dev/null 2>&1
useradd -m -s /bin/bash runner; echo "runner ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/runner
install -d -o runner -g runner /home/runner/tf /home/runner/.aws /home/runner/tmp /home/runner/repo
install -o runner -g runner -m 755 /opt/tf-src/terraform /home/runner/tf/terraform
install -o runner -g runner -m 600 /work/credentials /work/config /home/runner/.aws/
install -o runner -g runner -m 644 /work/hosts.txt /home/runner/hosts.txt
cp -a /repo/. /home/runner/repo/ && chown -R runner:runner /home/runner/repo
su runner -c "
set -e
export PATH=/home/runner/tf:\$PATH HOME=/home/runner RUNNER_TEMP=/home/runner/tmp AWS_REGION=\$REGION
export SANDBOX_EGRESS_HOSTS=/home/runner/hosts.txt SANDBOX_DEBUG_HOSTS_FILE=/home/runner/tmp/hosts.log
export SANDBOX_FAIL_ON_REFUSED=\${SANDBOX_FAIL_ON_REFUSED:-0}
/src/scripts/tf_sandbox.sh setup /home/runner/repo
/src/scripts/tf_sandbox.sh run \$TFDIR init -input=false -lockfile=readonly -no-color -backend-config=bucket=\$STATE_BUCKET -backend-config=region=\$STATE_REGION | tail -1
start=\$(date +%s)
timeout 900 /src/scripts/tf_sandbox.sh run \$TFDIR plan -input=false -lock=false -no-color -out=tfplan > /home/runner/tmp/plan.out 2>&1 && echo PLAN-OK || echo PLAN-FAILED rc=\$?
echo plan seconds: \$((\$(date +%s)-start))
grep -E \"^(Plan:|No changes|Error)\" /home/runner/tmp/plan.out | head -5
/src/scripts/tf_sandbox.sh egress-report
echo == hosts seen by the proxy:
sort /home/runner/tmp/hosts.log | uniq -c | sort -rn
"'
