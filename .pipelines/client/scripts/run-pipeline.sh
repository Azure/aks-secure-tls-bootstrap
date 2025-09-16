#!/bin/bash
set -euo pipefail
set +x

source .pipelines/client/scripts/common.sh

TEST_BRANCH="${TEST_BRANCH:-master}"
ADDITIONAL_VARS="${ADDITIONAL_VARS:-}"

[ -z "$ADO_ORGANIZATION" ] && echo "ADO_ORGANIZATION is empty" && exit 1
[ -z "$ADO_PROJECT" ] && echo "ADO_PROJECT is empty" && exit 1
[ -z "$ADO_PAT" ] && echo "ADO_PAT is empty" && exit 1
[ -z "$AZURE_DEVOPS_EXT_PAT" ] && echo "AZURE_DEVOPS_EXT_PAT is empty" && exit 1
[ -z "$SUITE_ID" ] && echo "SUITE_ID is empty" && exit 1

WAIT_SECONDS=300 # 5 minutes

main() {
  # retry 3 times, waiting 1 minute between attempts
  retrycmd_if_failure 3 60 runSuite || exit $?
}

runSuite() {
  RUN_FLAGS="--id $SUITE_ID --branch $TEST_BRANCH"
  if [ -n "${ADDITIONAL_VARS}" ]; then
    RUN_FLAGS="$RUN_FLAGS --variables $ADDITIONAL_VARS"
  fi

  echo "Set pipeline run flags: $RUN_FLAGS"

  RESPONSE=$(az pipelines run $RUN_FLAGS)
  if [ $? -ne 0 ]; then
    echo "Failed to queue new E2E run of pipeline: $SUITE_ID"
    return 1
  fi

  BUILD_ID=$(echo "$RESPONSE" | jq -r '.id')
  BUILD_URL="https://${ADO_ORGANIZATION}.visualstudio.com/${ADO_PROJECT}/_build/results?buildId=${BUILD_ID}&view=results"
  echo "E2E build URL: $BUILD_URL"

  STATUS="$(az pipelines runs show --id $BUILD_ID | jq -r '.status')"
  while [ "${STATUS,,}" = "notstarted" ] || [ "${STATUS,,}" = "inprogress" ]; do
    echo "build $BUILD_ID is still in-progress, will check again in $WAIT_SECONDS seconds"
    sleep $WAIT_SECONDS
    STATUS="$(az pipelines runs show --id $BUILD_ID | jq -r '.status')"
  done

  if [ "${STATUS,,}" != "completed" ]; then
    echo "E2E run $BUILD_ID finished with status \"$STATUS\": $BUILD_URL"
    return 1
  fi

  RESULT="$(az pipelines runs show --id $BUILD_ID | jq -r '.result')"
  if [ "${RESULT,,}" == "failed" ]; then
    echo "E2E run $BUILD_ID failed: $BUILD_URL"
    return 1
  fi
  if [ "${RESULT,,}" == "canceled" ]; then
    echo "E2E run $BUILD_ID was canceled: $BUILD_URL"
    return 1
  fi

  echo "E2E run $BUILD_ID finished with result \"$RESULT\": $BUILD_URL"
}

main "$@"