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
#   egress-report       print how many proxy connections were allowed/refused (counts only)
#   export DEST         copy the sandbox tree back (as root, symlinks kept as links, never
#                       followed) and chown it to the runner user; callers must treat it as
#                       untrusted (bundle.py skips links and non-regular files)
#
# Env passed into the sandbox: HOME, PATH (terraform's dir + system dirs), LANG, TF_IN_AUTOMATION,
# TF_INPUT, CHECKPOINT_DISABLE, HTTPS_PROXY/HTTP_PROXY (the egress proxy),
# AWS_REGION/AWS_DEFAULT_REGION (if set) and nothing else.
#
# Egress (Guardian M2): setup starts scripts/egress_proxy.py (as the runner user) on
# 127.0.0.1:$SANDBOX_PROXY_PORT and adds iptables/ip6tables rules that REJECT every packet from
# the sandbox uid except TCP to that port (no DNS, no IMDS, no direct internet). The proxy only
# relays CONNECT :443 to the EXACT hosts in $SANDBOX_EGRESS_HOSTS (scripts/egress_hosts.py) plus
# registry.terraform.io and releases.hashicorp.com. Setup fails (closed) if the host list is
# missing, the proxy can't bind, or the firewall can't be installed.
set -euo pipefail

SANDBOX_USER=${SANDBOX_USER:-tfsandbox}
SANDBOX_HOME=/home/$SANDBOX_USER
SANDBOX_PROXY_PORT=${SANDBOX_PROXY_PORT:-3128}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATS=${RUNNER_TEMP:-/tmp}/tf-sandbox-egress.json

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
    # Egress: our own proxy, started here (never trust whatever already listens on the port),
    # then the firewall. The proxy writes its pid to the ready file only after binding.
    hosts=${SANDBOX_EGRESS_HOSTS:-}
    [ -n "$hosts" ] && [ -s "$hosts" ] || die "SANDBOX_EGRESS_HOSTS (exact egress host list) is not set: refusing"
    ready="${RUNNER_TEMP:-/tmp}/tf-sandbox-proxy.ready"
    rm -f "$ready"
    nohup python3 -I "$HERE/egress_proxy.py" --port "$SANDBOX_PROXY_PORT" --hosts-file "$hosts" \
      --stats "$STATS" --ready-file "$ready" >/dev/null 2>"${RUNNER_TEMP:-/tmp}/tf-sandbox-proxy.err" &
    proxy_pid=$!
    for _ in $(seq 1 100); do
      [ -s "$ready" ] && break
      kill -0 "$proxy_pid" 2>/dev/null || break
      sleep 0.1
    done
    if ! { [ -s "$ready" ] && [ "$(cat "$ready")" = "$proxy_pid" ] && kill -0 "$proxy_pid" 2>/dev/null; }; then
      die "egress proxy did not start ($(head -c 200 "${RUNNER_TEMP:-/tmp}/tf-sandbox-proxy.err" 2>/dev/null))"
    fi
    uid=$(id -u "$SANDBOX_USER")
    for ipt in iptables ip6tables; do
      command -v "$ipt" >/dev/null || sudo test -x "/usr/sbin/$ipt" || die "$ipt not available"
      if ! sudo "$ipt" -C OUTPUT -m owner --uid-owner "$uid" -j REJECT 2>/dev/null; then
        sudo "$ipt" -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
      fi
    done
    if ! sudo iptables -C OUTPUT -m owner --uid-owner "$uid" -o lo -p tcp -d 127.0.0.1 \
        --dport "$SANDBOX_PROXY_PORT" -j ACCEPT 2>/dev/null; then
      sudo iptables -I OUTPUT 1 -m owner --uid-owner "$uid" -o lo -p tcp -d 127.0.0.1 \
        --dport "$SANDBOX_PROXY_PORT" -j ACCEPT
    fi
    ;;
  egress-report)
    if [ -f "$STATS" ]; then
      echo "sandbox egress (proxy connections): $(cat "$STATS")"
    else
      echo "sandbox egress: no proxy stats"
    fi
    ;;
  run)
    tfdir=${2:?usage: tf_sandbox.sh run TF_DIR ARGS...}
    shift 2
    case "$tfdir" in /*|*..*) die "TF_DIR must be relative" ;; esac
    tf=$(command -v terraform) || die "terraform not on PATH"
    tfbin=$(dirname "$(readlink -f "$tf")")
    envs=(HOME="$SANDBOX_HOME" PATH="$tfbin:/usr/local/bin:/usr/bin:/bin" LANG=C.UTF-8
          TF_IN_AUTOMATION=1 TF_INPUT=0 CHECKPOINT_DISABLE=1
          HTTPS_PROXY="http://127.0.0.1:$SANDBOX_PROXY_PORT" HTTP_PROXY="http://127.0.0.1:$SANDBOX_PROXY_PORT"
          https_proxy="http://127.0.0.1:$SANDBOX_PROXY_PORT" http_proxy="http://127.0.0.1:$SANDBOX_PROXY_PORT")
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
    die "usage: tf_sandbox.sh setup SRC_DIR | run TF_DIR ARGS... | egress-report | export DEST"
    ;;
esac
