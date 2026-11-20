#!/usr/bin/env bash
# Run Dovecot's imaptest compliance suite against a throwaway Picacho Server.
#
#   scripts/imaptest.sh            # all scripted tests
#   scripts/imaptest.sh fetch-body # one test (name of a file in src/tests)
#   STRESS=30 scripts/imaptest.sh  # also run a 30 s multi-client stress test
#
# Needs Docker (image dovecot/imaptest) and git. The test scripts are fetched
# from github.com/dovecot/imaptest into target/imaptest-src on first use.
set -euo pipefail
cd "$(dirname "$0")/.."

ROOT=$PWD
SRC=target/imaptest-src
DATA=target/imaptest-data
WEB=http://127.0.0.1:2880
PASS='Imaptest-Passw0rd'
IMAGE=${IMAPTEST_IMAGE:-dovecot/imaptest:latest}

[ -d "$SRC" ] || git clone --depth 1 https://github.com/dovecot/imaptest.git "$SRC"
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE"
# imaptest's own resolver can pick an unreachable address; pass an IPv4 literal.
HOST=${IMAPTEST_HOST:-$(docker run --rm --add-host=host.docker.internal:host-gateway --entrypoint sh "$IMAGE" \
  -c 'getent ahostsv4 host.docker.internal | head -1' | awk '{print $1}')}

cargo build --quiet
rm -rf "$DATA"
LOG=${IMAPTEST_LOG:-$(mktemp)}
./target/debug/picacho-server --config tests/imaptest.toml >"$LOG" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true; [ -n "${IMAPTEST_LOG:-}" ] || rm -f "$LOG"; rm -f "$JAR"' EXIT
JAR=$(mktemp)

for _ in $(seq 1 100); do
  KEY=$(grep -Eo '[A-Z2-9]{5}(-[A-Z2-9]{5}){4}' "$LOG" | head -1 || true)
  [ -n "$KEY" ] && break
  sleep 0.1
done
[ -n "${KEY:-}" ] || { cat "$LOG"; echo "server did not print an access key"; exit 1; }

api() { curl -sf -b "$JAR" -c "$JAR" -H 'Content-Type: application/json' -H 'X-Picacho: 1' "$@"; }

api -X POST "$WEB/api/setup/complete" -d "{\"key\":\"$KEY\",\"hostname\":\"localhost\",\"domain\":\"example.com\",\"admin_local\":\"postmaster\",\"admin_name\":\"Postmaster\",\"admin_password\":\"$PASS\"}" >/dev/null
# imaptest connects over plaintext from the Docker network.
api "$WEB/api/admin/settings" | python3 -c '
import json,sys
s=json.load(sys.stdin)["settings"]
s["security"]["require_tls_for_auth"]=False
s["security"]["max_auth_failures"]=100000
s["limits"]["max_imap_sessions_per_user"]=1000
s["limits"]["default_quota_mb"]=0
print(json.dumps(s))' | api -X PUT "$WEB/api/admin/settings" -d @- >/dev/null
for u in testuser testuser2; do
  api -X POST "$WEB/api/admin/accounts" -d "{\"email\":\"$u@example.com\",\"password\":\"$PASS\",\"quota_mb\":0}" >/dev/null
done

TESTS=/tests
[ $# -gt 0 ] && TESTS=/tests/$1
set +e
docker run --rm --add-host=host.docker.internal:host-gateway -v "$ROOT/$SRC/src/tests:/tests:ro" "$IMAGE" \
  host="$HOST" port=2143 user=testuser@example.com user2=testuser2@example.com pass="$PASS" test="$TESTS"
STATUS=$?
if [ -n "${STRESS:-}" ]; then
  docker run --rm --add-host=host.docker.internal:host-gateway -v "$ROOT/$SRC/src/tests:/tests:ro" "$IMAGE" \
    host="$HOST" port=2143 user=testuser@example.com pass="$PASS" mbox=/tests/default.mbox \
    clients=10 secs="$STRESS" logout=0 || STATUS=1
fi
grep -iE 'panic|error' "$LOG" | head -20 || true
exit $STATUS
