#!/bin/sh
# Provision a throwaway OpenSSH server for sshenc e2e tests.
#
# On startup:
#   - generate fresh host keys
#   - install authorized_keys from /authorized_keys (mounted) or
#     $AUTHORIZED_KEYS (env, newline-separated)
#   - run sshd in foreground (logs to stderr)
#
# The container is expected to run with `--rm` so state is ephemeral.

set -eu

ssh-keygen -A >/dev/null

AUTH_DST=/home/sshtest/.ssh/authorized_keys

if [ -f /authorized_keys ]; then
    cp /authorized_keys "$AUTH_DST"
elif [ -n "${AUTHORIZED_KEYS:-}" ]; then
    printf '%s\n' "$AUTHORIZED_KEYS" > "$AUTH_DST"
else
    echo "sshenc-e2e: no authorized_keys provided (mount /authorized_keys or set \$AUTHORIZED_KEYS)" >&2
    exit 64
fi

chmod 600 "$AUTH_DST"
chown sshtest:sshtest "$AUTH_DST"

exec /usr/sbin/sshd -D -e
