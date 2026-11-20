#!/usr/bin/env bash
# Run WebDAV/CalDAV/CardDAV conformance suites against a throwaway server.
#
#   scripts/davtest.sh            # litmus (WebDAV) + CalDAVTester (CalDAV/CardDAV)
#   scripts/davtest.sh litmus     # only litmus
#   scripts/davtest.sh caldav     # only CalDAVTester
#
# Needs Docker. Images are built from tests/docker/*.
set -euo pipefail
cd "$(dirname "$0")/.."

DATA=target/davtest-data
WEB=http://127.0.0.1:2881
PASS='Davtest-Passw0rd'
WHAT=${1:-all}

cargo build --quiet
rm -rf "$DATA"
LOG=${DAVTEST_LOG:-$(mktemp)}
./target/debug/picacho-server --config tests/davtest.toml >"$LOG" 2>&1 &
PID=$!
JAR=$(mktemp)
trap 'kill $PID 2>/dev/null || true; [ -n "${DAVTEST_LOG:-}" ] || rm -f "$LOG"; rm -f "$JAR"' EXIT

for _ in $(seq 1 100); do
  KEY=$(grep -Eo '[A-Z2-9]{5}(-[A-Z2-9]{5}){4}' "$LOG" | head -1 || true)
  [ -n "$KEY" ] && break
  sleep 0.1
done
[ -n "${KEY:-}" ] || { cat "$LOG"; echo "server did not print an access key"; exit 1; }

api() { curl -sf -b "$JAR" -c "$JAR" -H 'Content-Type: application/json' -H 'X-Picacho: 1' "$@"; }
api -X POST "$WEB/api/setup/complete" -d "{\"key\":\"$KEY\",\"hostname\":\"localhost\",\"domain\":\"example.com\",\"admin_local\":\"postmaster\",\"admin_name\":\"Postmaster\",\"admin_password\":\"$PASS\"}" >/dev/null
api "$WEB/api/admin/settings" | python3 -c '
import json,sys
s=json.load(sys.stdin)["settings"]
s["security"]["require_tls_for_auth"]=False
s["security"]["max_auth_failures"]=100000
s["limits"]["default_quota_mb"]=0
s["dav"]["default_quota_mb"]=0
print(json.dumps(s))' | api -X PUT "$WEB/api/admin/settings" -d @- >/dev/null
for u in user01 user02 user03; do
  api -X POST "$WEB/api/admin/accounts" -d "{\"email\":\"$u@example.com\",\"password\":\"$PASS\",\"quota_mb\":0}" >/dev/null
done
HOST=$(docker run --rm --add-host=host.docker.internal:host-gateway --entrypoint sh debian:bookworm-slim -c 'getent ahostsv4 host.docker.internal | head -1' | awk '{print $1}')

status=0
if [ "$WHAT" = all ] || [ "$WHAT" = litmus ]; then
  docker build -q -t picacho-litmus tests/docker/litmus >/dev/null
  # Touch the account once so its DAV homes exist.
  curl -sf -u "user01@example.com:$PASS" -X PROPFIND -H 'Depth: 0' "$WEB/dav/files/user01@example.com/" >/dev/null
  docker run --rm --add-host=host.docker.internal:host-gateway picacho-litmus --keep-going \
    "http://$HOST:2881/dav/files/user01@example.com/" "user01@example.com" "$PASS" || status=1
fi
if [ "$WHAT" = all ] || [ "$WHAT" = caldav ]; then
  # CalDAVTester's users: standalone DAV principals user01..user40, admin, apprentice.
  for u in admin apprentice $(seq -f 'user%02g' 1 40); do
    api -X POST "$WEB/api/v1/dav/principals" -d "{\"username\":\"$u\",\"password\":\"$PASS\",\"display_name\":\"$u\",\"email\":\"$u@example.com\",\"quota_mb\":100}" >/dev/null
  done
  mkdir -p target/dav-src
  [ -d target/dav-src/ccs-caldavtester ] || git clone -q --depth 1 https://github.com/apple/ccs-caldavtester.git target/dav-src/ccs-caldavtester
  [ -d target/dav-src/ccs-pycalendar ] || git clone -q --depth 1 https://github.com/apple/ccs-pycalendar.git target/dav-src/ccs-pycalendar
  docker build -q -t picacho-caldavtester -f tests/docker/caldavtester/Dockerfile target/dav-src >/dev/null
  sed -e "s/HOST/$HOST/" -e "s/PORT/2881/" -e "s/PASSWORD/$PASS/g" tests/docker/caldavtester/serverinfo.xml > target/davtest-serverinfo.xml
  CALDAV_TESTS=${CALDAV_TESTS:-"CalDAV/propfind.xml CalDAV/proppatch.xml CalDAV/put.xml CalDAV/get.xml CalDAV/delete.xml CalDAV/mkcalendar.xml CalDAV/copymove.xml CalDAV/reports.xml CalDAV/sync-report.xml CalDAV/conditional.xml CalDAV/ctag.xml CalDAV/current-user-principal.xml CalDAV/errors.xml CalDAV/bad-ical.xml CalDAV/floating.xml CalDAV/freebusy.xml CalDAV/recurrenceput.xml CalDAV/vtodos.xml CalDAV/well-known.xml CalDAV/nonascii.xml CalDAV/encodedURIs.xml CalDAV/options.xml CalDAV/depthreports.xml CalDAV/duplicate_uids.xml CalDAV/quota.xml CardDAV/propfind.xml CardDAV/proppatch.xml CardDAV/put.xml CardDAV/get.xml CardDAV/mkcol.xml CardDAV/copymove.xml CardDAV/reports.xml CardDAV/sync-report.xml CardDAV/current-user-principal.xml CardDAV/errors.xml CardDAV/well-known.xml CardDAV/nonascii.xml"}
  docker run --rm --add-host=host.docker.internal:host-gateway -v "$PWD/target/davtest-serverinfo.xml:/cdt/si.xml:ro" picacho-caldavtester \
    -s /cdt/si.xml -x /cdt/scripts/tests ${CALDAV_ARGS:-} $CALDAV_TESTS || status=1
fi
exit $status
