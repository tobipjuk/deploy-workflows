#!/usr/bin/env bash
# Sandbox separation test (needs docker): a hostile "terraform" must not see the runner's
# OIDC request token, runtime token, GITHUB_TOKEN, step scripts or .git, and must not sudo.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
image=${SANDBOX_TEST_IMAGE:-ubuntu:24.04}
docker run --rm -v "$root:/src:ro" "$image" bash -c '
  set -e
  apt-get update -qq >/dev/null && apt-get install -y -qq sudo >/dev/null
  useradd -m -s /bin/bash runner
  echo "runner ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/runner
  mkdir -p /opt/tool && cp /src/tests/sandbox/fake-terraform /opt/tool/terraform && chmod 755 /opt/tool/terraform
  su runner -c "PATH=/opt/tool:\$PATH HOME=/home/runner bash /src/tests/sandbox/inside.sh"
'
