#!/usr/bin/env bash
# Launch the V380 MJPEG client.
#
# The camera's IP is auto-detected (V380 native discovery, then by MAC) and
# re-resolved on every reconnect, so this keeps working across DHCP changes.
#
# Usage:  ./run-v380.sh              # uses HTTP_PORT from config.sh
#         ./run-v380.sh 8091         # override the port
#         ./run-v380.sh 8091 --debug # extra args are passed through
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f config.sh ]; then
	echo "error: no config.sh found." >&2
	echo "  cp config.example.sh config.sh   # then edit in your camera's details" >&2
	exit 1
fi
# shellcheck source=/dev/null
source ./config.sh

PORT="${1:-${HTTP_PORT:-8090}}"
[ $# -gt 0 ] && shift || true

echo "V380 client — device ${DEVICE_ID}, serving http://localhost:${PORT}/ (auto-detecting camera IP)"
exec node v380-mjpeg.js \
	--id "$DEVICE_ID" \
	--password "$PASSWORD" \
	${MAC:+--mac "$MAC"} \
	--http "$PORT" \
	"$@"
