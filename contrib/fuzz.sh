#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
# SPDX-License-Identifier: GPL-3.0-or-later

# Run all fuzz tests present in the repository.

MAX_LEN=4096
MAX_TOTAL_TIME=30 # Maximum time in seconds for each fuzz test to run.
TIMEOUT=10 # Timeout per fuzz iteration, to detect hangs, in seconds.

SOURCE=${BASH_SOURCE[0]}
while [ -L "$SOURCE" ]; do
  DIR=$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)
  SOURCE=$(readlink "$SOURCE")
  [[ $SOURCE != /* ]] && SOURCE=$DIR/$SOURCE
done
DIR=$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)

MANIFEST_PATHS=$(cargo metadata --format-version 1 | jq -r '.packages | map(select(.name | endswith("-fuzz"))) | .[].manifest_path')

for MANIFEST_PATH in ${MANIFEST_PATHS}; do
  MANIFEST_DIR=$(dirname "$MANIFEST_PATH")
  TARGETS=$(cd "$MANIFEST_DIR" && cargo fuzz list)
  for TARGET in ${TARGETS}; do
    echo "Fuzzing $TARGET"
    (cd "$MANIFEST_DIR" && cargo fuzz run "$TARGET" -- -max_len="$MAX_LEN" -timeout="$TIMEOUT" -max_total_time="$MAX_TOTAL_TIME")
  done
done
