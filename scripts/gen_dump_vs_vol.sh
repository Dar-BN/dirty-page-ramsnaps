#!/bin/bash

# Should have a continuous filename from 1 to N in the format
# "memory-dump=%05d.dmp.json"
find Poweliks WMIGhost -name memsnaps-all | \
    while read -r d; do
        (
        t="${d/\/memsnap*/}"
        t="${t//\// }"
        echo "${t}"
        cd "${d}" >/dev/null 2>&1 && \
        c=0
        last=$(ls -1 *.dmp.json | tail -1)
        dmp=$(printf "memory-dump-%05d.dmp.json" ${c})
        while [[ $dmp != $last ]]; do
            c=$(( c + 1 ))
            dmp=$(printf "memory-dump-%05d.dmp.json" ${c})
            if [[ -f ${dmp} ]]; then
                echo "1,1"
            else
                echo "1,0"
            fi
        done
        )
    done

# Should have a *.dmp or *.dmp.7z file
find Poweliks/Periodic WMIGhost/Periodic -name memsnaps | \
    while read -r d; do
        (
        t="${d/\/memsnap*/}"
        t="${t//\// }"
        cd "${d}" >/dev/null 2>&1 && \
        files=$(ls -1 *.dmp *.dmp.7z 2>/dev/null)
        if [[ -n "${files}" ]]; then
            echo "${t}"
            for f in ${files};do
                if [[ -f "${f}" ]]; then
                    if [[ -f ${f/.7z/}.json ]]; then
                        echo "1,1"
                    else
                        echo "1,0"
                    fi
                fi
            done
        fi
        )
    done


# When don't have the .dmp files, then fall back to run that was done by
# Cuckoo which always generates a file called 'vol-<timestamp>.json'
find Poweliks/Periodic WMIGhost/Periodic -name memsnaps | \
    while read -r d; do
        (
        t="${d/\/memsnap*/}"
        t="${t//\// }"
        cd "${d}" >/dev/null 2>&1 && \
        files=$(ls -1 vol*.json 2>/dev/null)
        if [[ -n "${files}" ]]; then
            echo "${t}"
            for f in ${files};do
                ts="${f/vol-/}"
                ts="${ts/.json/}"
                volf="$( printf "periodic-dump-%d.dmp.json" "${ts}" )"
                if [[ -f ${volf} ]]; then
                    echo "1,1"
                else
                    echo "1,0"
                fi
            done
        fi
        )
    done


