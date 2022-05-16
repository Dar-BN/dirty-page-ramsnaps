#!/bin/bash -xe


ls -1 pc-ram-*[0-9] > pc-ram-all.idx

qemu-process-ramsnaps \
    -p ../memsnaps-all/memory-dump \
    -i pc-ram-all.idx \
    -g 1 

cd ../memsnaps-all/

~/Workspaces/Research/run_volatility.py \
    -p Win7SP1x64 \
    -v /home/darrenk/.virtualenvs/cuckoo2/bin/vol.py \
    -t 4 \
    ./*.dmp 2>&1 | 
        tee vol.log

