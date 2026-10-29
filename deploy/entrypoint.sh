#!/bin/sh
# Starts the mlab-agent of this node with k3sec as its tool.
#   1. enrol once: the keys stay on the node (hostPath), never in the cluster;
#   2. write the agent policy from the ConfigMap template, k3sec pinned to the
#      SHA-256 of the binary in this (read-only) image;
#   3. run the agent, which starts `k3sec serve`.
set -eu

conf="${MLAB_AGENT_CONFIG_DIR:-/var/lib/mlab-agent}"
template="${K3SEC_POLICY_TEMPLATE:-/etc/k3sec/policy.toml}"
code_file="${MLAB_ENROLL_CODE_FILE:-/etc/mlab-enroll/code}"

mkdir -p "$conf"
chmod 0700 "$conf"

if [ -s "$code_file" ]; then
    mlab-agent --config "$conf" enroll --if-unenrolled \
        --server "${MLAB_SERVER:-https://mlab.sh}" \
        --code-file "$code_file" \
        --label "${NODE_NAME:-$(cat /proc/sys/kernel/hostname)}" \
        ${MLAB_FINGERPRINT:+--expect-fingerprint "$MLAB_FINGERPRINT"}
fi

sha="$(mlab-agent tools hash /usr/bin/k3sec)"
sed -e "s/@K3SEC_SHA256@/$sha/" -e "s/@NODE_NAME@/${NODE_NAME:-}/" "$template" > "$conf/policy.toml.tmp"
mv "$conf/policy.toml.tmp" "$conf/policy.toml"

exec mlab-agent --config "$conf" run
