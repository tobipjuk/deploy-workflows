#!/usr/bin/env bash
# Sandbox separation test (needs docker): a hostile "terraform" must not see the runner's
# OIDC request token, runtime token, GITHUB_TOKEN, step scripts or .git, must not sudo, and may
# reach the network only through the egress proxy (AWS + Terraform registry hosts).
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
image=${SANDBOX_TEST_IMAGE:-ubuntu:24.04}
docker run --rm --cap-add NET_ADMIN -v "$root:/src:ro" "$image" bash -c '
  set -e
  apt-get update -qq >/dev/null && apt-get install -y -qq sudo iptables python3 curl ca-certificates >/dev/null
  useradd -m -s /bin/bash runner
  echo "runner ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/runner
  # Like setup-terraform on hosted runners: the binary lives under the runner home (closed by setup).
  install -d -o runner -g runner /home/runner/work /home/runner/work/_temp /home/runner/work/_temp/tf
  install -o runner -g runner -m 755 /src/tests/sandbox/fake-terraform /home/runner/work/_temp/tf/terraform
  su runner -c "PATH=/home/runner/work/_temp/tf:\$PATH HOME=/home/runner SANDBOX_TF_VERSION=0.0.0-fake bash /src/tests/sandbox/inside.sh"
'
