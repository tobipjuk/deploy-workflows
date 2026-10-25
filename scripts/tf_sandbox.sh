#!/usr/bin/env bash
# Run Terraform as an unprivileged user with a scrubbed environment (Guardian review of f63cf2e).
#
# Project Terraform is written by people (and agents) the pipeline doesn't trust. HCL can read
# files (file("/proc/self/environ"), templatefile(...)) and providers run code, so Terraform
# must not see the runner's environment: ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN (mint OIDC tokens),
# ACTIONS_RUNTIME_TOKEN (artifacts), GITHUB_TOKEN, file-command paths. This script:
#
#   setup SRC_DIR       create user tfsandbox (no sudo, no docker), close the runner's home
#                       (0700), copy SRC_DIR (without .git) and the runner's ~/.aws (the OIDC
#                       session written by configure-aws-credentials) into the sandbox home
#   run TF_DIR ARGS...  sudo -u tfsandbox env -i ... terraform ARGS... in <sandbox>/src/TF_DIR;
#                       stdout/stderr come back to the caller
#   export DEST         copy the sandbox tree back (as root, symlinks kept as links, never
#                       followed) and chown it to the runner user; callers must treat it as
#                       untrusted (bundle.py skips links and non-regular files)
#
# Env passed into the sandbox: HOME, PATH (terraform's dir + system dirs), LANG, TF_IN_AUTOMATION,
# TF_INPUT, AWS_REGION/AWS_DEFAULT_REGION (if set) and nothing else.
set -euo pipefail

SANDBOX_USER=${SANDBOX_USER:-tfsandbox}
SANDBOX_HOME=/home/$SANDBOX_USER

die() { echo "::error::tf_sandbox: $*" >&2; exit 1; }

cmd=${1:-}
case "$cmd" in
  setup)
    src=${2:?usage: tf_sandbox.sh setup SRC_DIR}
    [ -d "$src" ] || die "no such directory: $src"
    if ! id -u "$SANDBOX_USER" >/dev/null 2>&1; then
      sudo useradd --create-home --user-group --shell /usr/sbin/nologin "$SANDBOX_USER"
    fi
    for g in $(id -nG "$SANDBOX_USER"); do
      case "$g" in sudo|admin|adm|docker|wheel|lxd|root) die "sandbox user is in group $g" ;; esac
    done
    if sudo -l -U "$SANDBOX_USER" 2>/dev/null | grep -q '(ALL'; then die "sandbox user has sudo rights"; fi
    # The runner's home holds the step scripts, runner files and its AWS profile.
    sudo chmod 0700 "$HOME"
    sudo rm -rf "$SANDBOX_HOME/src" "$SANDBOX_HOME/.aws"
    sudo mkdir -p "$SANDBOX_HOME/src"
    tar -C "$src" --exclude=./.git -cf - . | sudo tar -C "$SANDBOX_HOME/src" --no-same-owner -xf -
    if [ -d "$HOME/.aws" ]; then sudo cp -a "$HOME/.aws" "$SANDBOX_HOME/.aws"; fi
    sudo chown -R -h "$SANDBOX_USER:$SANDBOX_USER" "$SANDBOX_HOME"
    sudo chmod 0700 "$SANDBOX_HOME"
    ;;
  run)
    tfdir=${2:?usage: tf_sandbox.sh run TF_DIR ARGS...}
    shift 2
    case "$tfdir" in /*|*..*) die "TF_DIR must be relative" ;; esac
    tf=$(command -v terraform) || die "terraform not on PATH"
    tfbin=$(dirname "$(readlink -f "$tf")")
    envs=(HOME="$SANDBOX_HOME" PATH="$tfbin:/usr/local/bin:/usr/bin:/bin" LANG=C.UTF-8
          TF_IN_AUTOMATION=1 TF_INPUT=0)
    [ -z "${AWS_REGION:-}" ] || envs+=(AWS_REGION="$AWS_REGION" AWS_DEFAULT_REGION="$AWS_REGION")
    # shellcheck disable=SC2016  # $1/$@ expand inside the sandbox shell
    sudo -n -u "$SANDBOX_USER" -H -- env -i "${envs[@]}" \
      bash --noprofile --norc -c 'cd "$1" && shift && exec terraform "$@"' _ "$SANDBOX_HOME/src/$tfdir" "$@"
    ;;
  export)
    dest=${2:?usage: tf_sandbox.sh export DEST}
    sudo rm -rf "$dest"
    sudo mkdir -p "$dest"
    sudo cp -a --no-dereference "$SANDBOX_HOME/src/." "$dest/"
    sudo chown -R -h "$(id -u):$(id -g)" "$dest"
    ;;
  *)
    die "usage: tf_sandbox.sh setup SRC_DIR | run TF_DIR ARGS... | export DEST"
    ;;
esac
