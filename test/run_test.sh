#!/bin/sh

GOLDYHOST=127.0.0.1
GOLDYPORT=29501
BACKENDHOST=127.0.0.1
BACKENDPORT=29502

goldypid=
backendpid=
testdir=$(dirname $0)
cd $testdir/..

log() {
  echo "# $@"
}

kill_goldy() {
  log "Killing goldy (PID $goldypid)"
  kill $goldypid
  wait $goldypid
  goldypid=
}

kill_backend() {
  log "Killing backend test server (PID $backendpid)"
  kill $backendpid
  wait $backendpid
  backendpid=
}

cleanup() {
  if [ -n "$goldypid" ] ; then
    kill_goldy
  fi
  if [ -n "$backendpid" ] ; then
    kill_backend
  fi
  rm -f test/log/*.log
}

handle_signal() {
  log "Stopping..."
  cleanup
  log "Stopped"
  exit 1
}

test_one_packet() {
  testnum=$1
  description=$2
  packet=$3
  test/dtls_test_client -n goldy.local -h $GOLDYHOST -p $GOLDYPORT -b "$packet" > test/log/test_client.log

  actual_line=$(grep 'bytes read' test/log/test_client.log)

  expected_packet=$(echo -n "$packet" | rev)
  expected_packet_len=${#expected_packet}
  expected_line="dtls_test_client: $expected_packet_len bytes read: '$expected_packet'"
  if [ "$actual_line" != "$expected_line" ] ; then
    echo "not ok $testnum - $description"
    echo "  Expected \"$expected_line\" but got \"$actual_line\""
    return 1
  fi
  echo "ok $testnum - $description"
  return 0
}

trap handle_signal INT TERM HUP

log "Starting goldy..."
./goldy -l $GOLDYHOST:$GOLDYPORT -b $BACKENDHOST:$BACKENDPORT -c test/keys/test-proxy-cert.pem -k test/keys/test-proxy-key.pem > test/log/goldy.log &
goldypid=$!

log "Starting test UDP backend server..."
test/udp_test_server.pl -b $BACKENDHOST:$BACKENDPORT > test/log/test_server.log &
backendpid=$!

log "Waiting for goldy and backend server to start..."
sleep 1

failures=0

# Output test results in TAP format
echo "1..4"

test_one_packet 1 "Small packet 1" "A"
failures=$((failures+$?))

test_one_packet 2 "Small packet 2" "Please reverse this message body"
failures=$((failures+$?))

test_one_packet 3 "Medium packet" "123456789012345678901234567890123456789012345678901234567890"
failures=$((failures+$?))

big_packet=$(printf '%1200s') # 1200 spaces
test_one_packet 4 "Big packet" "A${big_packet}Z"
failures=$((failures+$?))

cleanup

log "Done: Failures: $failures"
exit $failures
