#!/bin/bash

retrycmd_if_failure() {
    retries=$1; wait_sleep=$2; shift && shift
    for i in $(seq 1 $retries); do
        "${@}" && break || \
        echo "Failed to execute command \"$@\""
        if [ $i -eq $retries ]; then
            echo "ERROR: Exhausted all retries (${i}/${retries})"
            return 1
        else
            echo "$(($retries - $i)) retries remaining"
            sleep $wait_sleep
        fi
    done
    echo Executed \"$@\" $i times;
}