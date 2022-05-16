#!/bin/bash

if [[ ! -d "${1}/ramsnaps" ]]; then
    echo "No such dir '${1}/ramsnaps'"
    exit 1
fi

cd "${1}/ramsnaps" && \
    stat -c "%n,%s" pc-ram-[0-9]*[0-9]
