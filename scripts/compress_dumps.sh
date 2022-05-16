#!/bin/bash

MATCH="*.dmp"

if [[ "${1}" == "-n" ]]; then
    DEBUG="echo DEBUG:" 
    shift
fi

if [[ -n "${1}" ]]; then
    MATCH="${1}"
    shift
fi

find . -name "${MATCH}" | \
    while read -r f; do
        case "${f}" in 
            *.7z)
                echo "${f} is already compressed, skipping..."
                ;;
            *)
                ${DEBUG} 7z a -sdel -mmt4 "${f}.7z" "${f}"
                ;;
        esac
    done
