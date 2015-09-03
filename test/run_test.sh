#!/bin/bash

GOLDYHOST=127.0.0.1
GOLDYPORT=29501
BACKENDHOST=127.0.0.1
BACKENDPORT=29502

usage() {
	  cat << EOF
usage: $0 options

Runs the goldy test suite

OPTIONS:
   -h/?    Show this message
   -l      keep log files after running
   -k      kill processes using pkill
EOF

}

keep_log_files=0
pkill_processes=0

while getopts "kl" OPTION
do
    case $OPTION in
        l)
            keep_log_files=1
			      echo "Keeping log files"
            ;;
        k)
            pkill_processes=1
			      echo "Will use pkill"
            ;;
        h)
            usage
            exit 1
            ;;
        ?)
            usage
            exit
            ;;
    esac
done

goldypid=
backendpid=
testdir=$(dirname $0)
cd $testdir/..

log() {
  echo "# $@"
}

kill_goldy() {
  log "Killing goldy (PID $goldypid)"
  if [ $pkill_processes ] ; then
    pkill goldy
  else
    kill $goldypid
    wait $goldypid
  fi
  goldypid=
}

kill_backend() {
  log "Killing backend test server (PID $backendpid)"
  if [ $pkill_processes ] ; then
    pkill -f udp_test_server.pl
  else
    kill $backendpid
    wait $backendpid
  fi
  backendpid=
}

cleanup() {
  if [ -n "$goldypid" ] ; then
    kill_goldy
  fi
  if [ -n "$backendpid" ] ; then
    kill_backend
  fi
  if [ $keep_log_files != 1 ]; then
    rm -f test/log/*.log
  fi
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
  test/dtls_test_client -n goldy.local -h $GOLDYHOST -p $GOLDYPORT -b "$packet" > test/log/test_client.log 2>&1

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
./goldy -l $GOLDYHOST:$GOLDYPORT -b $BACKENDHOST:$BACKENDPORT -c test/keys/test-proxy-cert.pem -k test/keys/test-proxy-key.pem > test/log/goldy.log 2>&1 &
goldypid=$!

log "Starting test UDP backend server..."
test/udp_test_server.pl -b $BACKENDHOST:$BACKENDPORT > test/log/test_server.log 2>&1 &
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

many_spaces=$(printf '%1200s') # 1200 spaces
test_one_packet 4 "Big packet" "A${many_spaces}Z"
failures=$((failures+$?))

cleanup

log "Done: Failures: $failures"
exit $failures
