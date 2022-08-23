#! /bin/bash

SRC_DIR="${1}"
ZPID_FILE="/tmp/ztest.pid"

BIN_PS="$(which ps)"
BIN_RM="$(which rm)"
BIN_CAT="$(which cat)"
BIN_KILL="$(which kill)"
BIN_XARGS="$(which xargs)"
BIN_PRINTF="$(which printf)"


${BIN_RM} "${ZPID_FILE}"
"${SRC_DIR}/test/zombie" & echo "${!}" >"${ZPID_FILE}"

ZPPID="$("${BIN_CAT}" "${ZPID_FILE}")"
ZOMBIES="$("${BIN_PS}" -o pid --no-headers --ppid "${ZPPID}")"
ARGS="$(echo -n "${ZOMBIES}" | "${BIN_XARGS}" "${BIN_PRINTF}" -- ' -z %s')"

"${SRC_DIR}/zreap" -p "${ZPPID}" ${ARGS}
if "${BIN_PS}" -o pid --no-headers --ppid "${ZPPID}"; then
	echo "FAIL";
else
	echo "PASS";
fi

kill -15 "${ZPPID}"
