#!/bin/bash

GOLDYHOST=127.0.0.1
GOLDYPORT=29501
BACKENDHOST=127.0.0.1
BACKENDPORT=29502

usage() {
  cat << EOF
Usage: $0 [options]

Runs the goldy test suite

OPTIONS:
   -h/?    Show this message
   -l      keep log files after running
   -k      kill processes using pkill
   -s      skip log (keep stderr)
   -t      skip test client/server log (keep test client/server stderr)
EOF

}

keep_log_files=0
pkill_processes=0
keep_stderr=0
keep_test_stderr=0

while getopts "klst" OPTION
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
    s)
      keep_stderr=1
      echo "Will not capture stderr"
      ;;
    t)
      keep_test_stderr=1
      echo "Will not capture stderr for test client(s)"
      ;;
    h)
      usage
      exit 1
      ;;
    ?)
      usage
      exit 1
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
  if [ $pkill_processes = 1 ] ; then
    pkill goldy
  else
    kill $goldypid
    wait $goldypid
  fi
  goldypid=
}

kill_backend() {
  log "Killing backend test server (PID $backendpid)"
  if [ $pkill_processes = 1 ] ; then
    pkill udp_test_server
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

log_goldy_mem_usage() {
  if [ -z "$goldypid" ] ; then
    return
  fi
  log "goldy (PID $goldypid) resource usage (RSS VSZ %CPU): $(ps -p $goldypid -o rss= -o vsz= -o %cpu=)"
}

now_ms() {
  date +'%s-%N' | sed -e 's/^\([0-9]*\)-\([0-9][0-9][0-9]\).*$/\1\2/'
}

run_concurrent_client_scenarios() {
  testnum=$1
  description=$2
  duplicates=$3
  clients_scenarios=${@:4}
  echo "=============================================== concurrent scenarios"
  log_goldy_mem_usage
  starttime=$(now_ms)
  pids=""
  for i in $(eval echo "{1..$duplicates}") ; do
    for scenario in $clients_scenarios ; do
      if [ $keep_test_stderr == 1 ]; then
        test/dtls_test_client -n goldy.local -h $GOLDYHOST -p $GOLDYPORT -s "$scenario" &
      else
        test/dtls_test_client -n goldy.local -h $GOLDYHOST -p $GOLDYPORT -s "$scenario" >> test/log/test_client.log 2>&1 &
      fi
      pids="$pids $!"
    done
  done

  # Optimistic approach
  exitcode=0

  for clientpid in $pids ; do
    wait $clientpid
    clientexitcode=$?
    if [ $clientexitcode != 0 ] ; then
      exitcode=1
    fi
  done
  log_goldy_mem_usage
  echo "=============================================== results"
  endtime=$(now_ms)
  log "Test $testnum took $((endtime - starttime)) milliseconds"
  if [ $exitcode != 0 ] ; then
    echo "not ok $testnum - $description"
    return 1
  fi
  echo "ok $testnum - $description"
  return 0
}

trap handle_signal INT TERM HUP

log "Starting goldy..."
redirect_line=""
if [ $keep_stderr == 1 ]; then
  ./goldy -g DEBUG -l $GOLDYHOST:$GOLDYPORT -b $BACKENDHOST:$BACKENDPORT -c test/keys/test-proxy-cert.pem -k test/keys/test-proxy-key.pem &
else
  ./goldy -g DEBUG -l $GOLDYHOST:$GOLDYPORT -b $BACKENDHOST:$BACKENDPORT -c test/keys/test-proxy-cert.pem -k test/keys/test-proxy-key.pem > test/log/goldy.log 2>&1 &
fi

goldypid=$!

log "Starting test UDP backend server..."
if [ $keep_test_stderr == 1 ]; then
  test/udp_test_server -p $BACKENDPORT &
else
  test/udp_test_server -p $BACKENDPORT > test/log/test_server.log 2>&1 &
fi
backendpid=$!

log "Waiting for goldy and backend server to start..."
sleep 1

failures=0

# Note: in order to avoid bash quoting hell, we're avoiding spaces in the
# client scenarios. This means that each argument ("word") is one scenario
# which will be run in its own client.

many_spaces=$(printf '%1200s' | tr ' ' '_') # 1200 underscores
big_packet="A${many_spaces}Z"
four_packets="ABCDEF,sleep=50,serverdelay=200_GHIJKL,sleep=50,MNOPQRS,sleep=50,serverdelay=200_TUVWXYZ"
three_big_packets="$big_packet,sleep=100,serverdelay=200_$big_packet,sleep=100,$big_packet"

# Output test results in TAP format
echo "1..9"

run_concurrent_client_scenarios 1 "Small packet 1" 1 "A"
failures=$((failures+$?))

run_concurrent_client_scenarios 2 "Small packet 2" 1 "Please_reverse_this_message_body"
failures=$((failures+$?))

run_concurrent_client_scenarios 3 "Medium packet" 1 "123456789012345678901234567890123456789012345678901234567890"
failures=$((failures+$?))

run_concurrent_client_scenarios 4 "Big packet" 1 "$big_packet"
failures=$((failures+$?))

run_concurrent_client_scenarios 5 "4 small sequential packets" 1 \
  "ABCDEF,sleep=100,GHIJKL,sleep=200,MNOPQRS,sleep=100,TUVWXYZ"
failures=$((failures+$?))

run_concurrent_client_scenarios 6 "3 parallel client with 4 distinct small packets" 1 \
  "ABCDEF,sleep=100,GHIJKL,sleep=200,MNOPQRS,sleep=100,TUVWXYZ" \
  "123456,sleep=100,7890AB,sleep=100,CDEFGHI,sleep=150,JKLMNOP" \
  "ZYXWVU,sleep=50,TSRQPO,sleep=200,NMLKJIH,sleep=150,GFEDCBA"
failures=$((failures+$?))

run_concurrent_client_scenarios 7 "10 identical parallel clients with 4 small packets each" 10 "$four_packets"
failures=$((failures+$?))

run_concurrent_client_scenarios 8 "4 small clients and 4 big clients (all in parallel)" 4 \
  "repeat=5,$four_packets" "repeat=5,$three_big_packets"
failures=$((failures+$?))

run_concurrent_client_scenarios 9 "50 identical parallel clients with 4 small packets each" 50 "$four_packets"
failures=$((failures+$?))

cleanup

log "Done: Failures: $failures"
exit $failures
