#!/usr/bin/env bash
# Runs inside a throwaway ubuntu container as user "runner" (see run.sh).
set -euo pipefail
export ACTIONS_ID_TOKEN_REQUEST_TOKEN=oidc-request-secret-123
export ACTIONS_ID_TOKEN_REQUEST_URL=https://example.invalid/token
export ACTIONS_RUNTIME_TOKEN=runtime-secret-456
export GITHUB_TOKEN=ghs-secret-789
export AWS_REGION=eu-west-2
mkdir -p "$HOME/work/repo/infra" "$HOME/.aws" "$HOME/work/_temp"
echo "[default]" > "$HOME/.aws/credentials"; echo "aws_access_key_id = AKIAEXAMPLE" >> "$HOME/.aws/credentials"
echo "step-script-secret oidc-request-secret-123" > "$HOME/work/_temp/step.sh"
echo 'resource "x" "y" {}' > "$HOME/work/repo/infra/main.tf"
mkdir -p "$HOME/work/repo/.git" && echo gitsecret > "$HOME/work/repo/.git/config"
chmod 0755 "$HOME"   # like a permissive runner image; setup must close it

export RUNNER_TEMP="$HOME/work/_temp"
printf 'sts.amazonaws.com\n' > "$RUNNER_TEMP/egress-hosts.txt"
fail=0
# LOW-1: something else already on the proxy port -> setup must refuse, not trust it
python3 -c 'import socket,time; s=socket.socket(); s.bind(("127.0.0.1",3128)); s.listen(5); time.sleep(30)' &
squatter=$!
sleep 1
if SANDBOX_EGRESS_HOSTS="$RUNNER_TEMP/egress-hosts.txt" /src/scripts/tf_sandbox.sh setup "$HOME/work/repo" 2>/dev/null; then
  echo "FAIL: setup trusted a foreign listener on the proxy port"; fail=1
fi
kill "$squatter"; wait "$squatter" 2>/dev/null || true
# no host list -> refuse
if /src/scripts/tf_sandbox.sh setup "$HOME/work/repo" 2>/dev/null; then echo "FAIL: setup ran without a host list"; fail=1; fi
SANDBOX_EGRESS_HOSTS="$RUNNER_TEMP/egress-hosts.txt" /src/scripts/tf_sandbox.sh setup "$HOME/work/repo"
out=$(/src/scripts/tf_sandbox.sh run infra probe 2>&1 || true)
while IFS= read -r l; do echo "  sandbox: $l"; done <<< "$out"
for s in oidc-request-secret-123 runtime-secret-456 ghs-secret-789 step-script-secret gitsecret; do
  if grep -q "$s" <<< "$out"; then echo "FAIL: sandbox saw $s"; fail=1; fi
done
grep -q "PWD-OK infra" <<< "$out" || { echo "FAIL: terraform did not run in the sandbox copy"; fail=1; }
v=$(/src/scripts/tf_sandbox.sh run infra version 2>&1 | head -n1)
[ "$v" = "Terraform v0.0.0-fake" ] || { echo "FAIL: sandbox can't resolve terraform ($v)"; fail=1; }
[ "$(stat -c %U /usr/local/lib/tf-sandbox/terraform)" = root ] || { echo "FAIL: sandbox terraform not root-owned"; fail=1; }
grep -q "AWSCREDS-OK" <<< "$out" || { echo "FAIL: sandbox lacks the AWS profile"; fail=1; }
grep -q "REGION eu-west-2" <<< "$out" || { echo "FAIL: AWS_REGION not passed"; fail=1; }
grep -q "SUDO-DENIED" <<< "$out" || { echo "FAIL: sandbox could sudo"; fail=1; }
for want in EGRESS-DIRECT-BLOCKED DNS-BLOCKED PROXY-FOREIGN-BLOCKED PROXY-IMDS-BLOCKED PROXY-UNLISTED-AWS-BLOCKED; do
  grep -q "$want" <<< "$out" || { echo "FAIL: expected $want"; fail=1; }
done
if [ "${SANDBOX_TEST_OFFLINE:-}" != 1 ]; then
  grep -q "PROXY-AWS-OK" <<< "$out" || { echo "FAIL: AWS endpoint not reachable through the proxy"; fail=1; }
fi
/src/scripts/tf_sandbox.sh egress-report
# export keeps links as links
/src/scripts/tf_sandbox.sh export "$HOME/work/out"
[ -L "$HOME/work/out/infra/evil-link" ] || { echo "FAIL: symlink not preserved as link"; fail=1; }
[ -f "$HOME/work/out/infra/tfplan" ] && [ "$(stat -c %U "$HOME/work/out/infra/tfplan")" = runner ] || { echo "FAIL: export ownership"; fail=1; }
[ "$fail" = 0 ] && echo "SANDBOX TEST PASSED"
exit "$fail"
