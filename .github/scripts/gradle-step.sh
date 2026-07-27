#!/usr/bin/env bash
set -uo pipefail

task_name="$1"
log_file="gradle-${task_name//:/-}.log"

set +e
./gradlew "$@" --console=plain 2>&1 | tee "$log_file"
status=${PIPESTATUS[0]}
set -e

if [[ $status -ne 0 ]]; then
  message="$(tail -n 100 "$log_file")"
  message="${message//'%'/'%25'}"
  message="${message//$'\r'/'%0D'}"
  message="${message//$'\n'/'%0A'}"
  echo "::error title=Gradle ${task_name} failed::${message}"
fi

exit "$status"
