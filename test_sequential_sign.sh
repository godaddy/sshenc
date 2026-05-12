#!/bin/bash
set -e

# Test script to reproduce the sequential signing issue

PUBKEY="$HOME/.ssh/id_ecdsa.pub"

if [ ! -f "$PUBKEY" ]; then
    echo "Error: $PUBKEY not found"
    exit 1
fi

echo "Testing 30 sequential sign operations..."
mkdir -p /tmp/sshenc-sign-test
cd /tmp/sshenc-sign-test

for i in $(seq 1 30); do
    echo "Sign $i of 30"
    DATA="test-data-$i.txt"
    echo "test data $i" > "$DATA"

    if ! sshenc -Y sign -n git -f "$PUBKEY" "$DATA" 2>&1; then
        echo "FAILED at iteration $i"
        exit 1
    fi

    if [ ! -f "${DATA}.sig" ]; then
        echo "ERROR: Signature file not created for iteration $i"
        exit 1
    fi
done

echo "SUCCESS: All 30 signs completed"
cd -
rm -rf /tmp/sshenc-sign-test
