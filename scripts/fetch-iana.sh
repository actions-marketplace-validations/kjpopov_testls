#!/bin/sh
# Refresh the IANA TLS registry snapshots used by testls-data.
set -eu
dir="$(dirname "$0")/../crates/testls-data/iana"
base="https://www.iana.org/assignments/tls-parameters"
for f in tls-parameters-4.csv tls-parameters-8.csv tls-signaturescheme.csv; do
    curl -sSfL -o "$dir/$f" "$base/$f"
done
python3 "$(dirname "$0")/gen-iana.py"
