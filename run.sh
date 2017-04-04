#!/bin/sh

PYTHON=

function find() {
    name="$1"
    which "${name}" 2>/dev/null 1>&2
}

function check_python() {
    name="$1"

    if find "${name}"; then
        if "${name}" --version 2>&1 | grep -q 'Python 2\.7'; then
            PYTHON="${name}"
            return 0
        fi
    fi

    return 1
}

function find_python() {
    for p in pypy pypy2 python2 python; do
        if check_python "$p"; then
            return
        fi
    done

    echo "Can't find python interpreter" 1>&2
    PYTHON=python2
}

find_python
echo "Using ${PYTHON} as python interpreter" 1>&2

exec "${PYTHON}" ./src/process_log.py --input log_input/log.txt \
                                      --output-directory log_output "$@"
