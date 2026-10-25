#!/usr/bin/env bash
# Optional (needs docker + network): a real `terraform init` + `plan` (hashicorp/random) inside the
# sandbox, through the egress proxy only. Proves the allowlist covers provider downloads.
#   TF_BIN=$(mise which terraform) tests/sandbox/real-terraform.sh
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tf=${TF_BIN:?set TF_BIN to a linux terraform binary}
docker run --rm --cap-add NET_ADMIN -v "$root:/src:ro" -v "$tf:/opt/tf-src/terraform:ro" ubuntu:24.04 bash -c '
set -e
apt-get update -qq >/dev/null && apt-get install -y -qq sudo iptables python3 curl ca-certificates >/dev/null
useradd -m -s /bin/bash runner; echo "runner ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/runner
install -d -o runner -g runner /home/runner/tf && install -o runner -g runner -m 755 /opt/tf-src/terraform /home/runner/tf/terraform
su runner -c "
set -e
export PATH=/home/runner/tf:\$PATH HOME=/home/runner RUNNER_TEMP=/home/runner/tmp
mkdir -p \$RUNNER_TEMP ~/repo/infra
printf %s\\\\n \"terraform {\" \"  required_providers {\" \"    random = { source = \\\"hashicorp/random\\\", version = \\\"3.7.2\\\" }\" \"  }\" \"}\" \"resource \\\"random_id\\\" \\\"x\\\" { byte_length = 4 }\" > ~/repo/infra/main.tf
printf sts.amazonaws.com\\\\n > \$RUNNER_TEMP/egress-hosts.txt
SANDBOX_EGRESS_HOSTS=\$RUNNER_TEMP/egress-hosts.txt /src/scripts/tf_sandbox.sh setup ~/repo
/src/scripts/tf_sandbox.sh run infra init -input=false -no-color | tail -1
/src/scripts/tf_sandbox.sh run infra plan -input=false -no-color -out=tfplan | grep Plan:
/src/scripts/tf_sandbox.sh egress-report
"'
