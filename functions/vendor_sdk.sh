#!/usr/bin/env sh
# Copy the zero-dependency SDK into every function folder before `faas-cli build/up`.
set -e
cd "$(dirname "$0")"
for d in auth-check payment-process image-resize notify-user data-export; do
  cp ../sdk/ssmf_sdk.py "$d/ssmf_sdk.py"
done
echo "SDK vendored into all functions."
