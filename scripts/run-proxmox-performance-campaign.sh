#!/usr/bin/env bash
# Ephemeral Proxmox performance campaign for #593.
#
# Canonical mode provisions a disposable KVM VM. LXC remains available only as
# an explicit smoke mode for cheap orchestration checks.
set -euo pipefail
