#!/bin/bash

RAMSNAP=""

run_cuckoo() {
    cuckoo submit \
        --timeout 120 \
        --enforce-timeout \
        --memory \
        --max 1 \
        --platform windows \
        --options="route=inetsim,procmemdump=yes${RAMSNAP}${FREQ}" \
        "$@"
}

while [[ "$1" == -* ]]; do
    case "${1}" in
        -r)
            RAMSNAP=",ramsnap=yes"
            ;;
        -f)
            FREQ=",frequency=${2}"
            shift
            ;;
        -F)
            FILTER="-i!${2}"
            shift
            ;;
    esac
    shift
done

if [[ -z "$*" ]]; then
    echo "No files specified"
    exit 1
fi

_SUB_DIR="$(mktemp -t -d cuckoosub.XXXXXXXXX)"

echo "Using submission dir: '${_SUB_DIR}'"

for f in "$@"; do
    case "${f}" in
        *.zip)
            echo "Extracting '${f}' into '${_SUB_DIR}"
            # unzip -d "${_SUB_DIR}" "${f}"
            7z e -pinfected ${FILTER} -o"${_SUB_DIR}" "${f}"
            ;;
        *)
            echo "Copying '${f}' into '${_SUB_DIR}"
            cp -p "${f}" "${_SUB_DIR}"
            ;;
    esac
done

set -x
find "${_SUB_DIR}" -type f | \
    while read -r f; do
        extns="$(file -b --extension "${f}")"
        extn="${extns/\/*/}"
        case "${f}" in
            *.bin)
                mv "${f}" "${f/.bin/}.${extn}"
                ;;
            *)
                ;;
        esac
    done


run_cuckoo "${_SUB_DIR}"
