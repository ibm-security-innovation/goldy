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
   -n      run specific test - N
   -v      run goldy under valgrind
EOF

}

keep_log_files=0
pkill_processes=0
keep_stderr=0
keep_test_stderr=0
use_valgrind=0
test_num=0

while getopts "klstvn:" OPTION
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
    v)
      use_valgrind=1
      echo "Will run goldy under valgrind"
      ;;
    n)
      test_num=$OPTARG
      echo "running only test $test_num"
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
  m=( $(ps -p $goldypid -o rss= -o vsz=) )
  udp_stats="-"
  if [ -f /proc/$goldypid/net/sockstat ] ; then
    udp_stats="$(grep ^UDP: /proc/$goldypid/net/sockstat)"
  fi
  log "goldy (PID $goldypid) resource usage: Memory RSS=${m[0]} KB, Memory VSZ=${m[1]} KB, $udp_stats"
}

now_ms() {
  $date_binary +'%s-%N' | sed -e 's/^\([0-9]*\)-\([0-9][0-9][0-9]\).*$/\1\2/'
}

run_test_file() {
  filename=$1
  testnum=$(basename $filename)
  unset DESCRIPTION
  unset DUPLICATES
  for v in ${!CLIENT_*} ; do
    unset $v
  done

  . $filename

  if [ -z "$DUPLICATES" ] ; then
    DUPLICATES=1
  fi

  log "=============================================== concurrent scenarios"
  log_goldy_mem_usage
  starttime=$(now_ms)
  pids=""

  for d in $(eval echo "{1..$DUPLICATES}") ; do
    for v in ${!CLIENT_*} ; do
      scenario="${!v}"
      if [ -n "$scenario" ] ; then
        if [ $keep_test_stderr == 1 ]; then
          test/dtls_test_client -n goldy.local -h $GOLDYHOST -p $GOLDYPORT -s "$scenario" &
        else
          test/dtls_test_client -n goldy.local -h $GOLDYHOST -p $GOLDYPORT -s "$scenario" >> test/log/test_client.log 2>&1 &
        fi
        pids="$pids $!"
      fi
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

  endtime=$(now_ms)
  log_goldy_mem_usage
  log "=============================================== results"
  log "$testnum took $((endtime - starttime)) $time_resolution"
  if [ $exitcode != 0 ] ; then
    echo "not ok $testnum - $DESCRIPTION"
    return 1
  fi
  echo "ok $testnum - $DESCRIPTION"
  return 0
}

trap handle_signal INT TERM HUP

date_binary=date
time_resolution=millisecs
if [[ `uname` == "Darwin" ]] ; then
  # OSX doesn't have date with millisecs precision so we'll search for gdate
  # and opt for it if it is there, otherwise settle for date's whole-second resolution
  which gdate > /dev/null 2>&1
  if [[ $? == 0 ]]; then
    log "Using gdate"
    date_binary=gdate
  else
    time_resolution=secs
  fi
fi

log "Starting goldy..."
valgrind_cmd=""
if [ $use_valgrind == 1 ] ; then
  valgrind_cmd="valgrind --leak-check=full --show-reachable=yes -v"
fi
goldy_cmdline="./goldy -g DEBUG -l $GOLDYHOST:$GOLDYPORT -b $BACKENDHOST:$BACKENDPORT -c test/keys/test-proxy-cert.pem -k test/keys/test-proxy-key.pem"
if [ $keep_stderr == 1 ]; then
  $valgrind_cmd $goldy_cmdline &
else
  $valgrind_cmd $goldy_cmdline > test/log/goldy.log 2>&1 &
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
if [[ $test_num == 0 ]] ; then
  for f in test/tests/test-* ; do
    run_test_file $f
    failures=$((failures+$?))
  done
else
  run_test_file `printf "test/tests/test-%02d" $test_num`
  failures=$((failures+$?))
fi

cleanup

log "Done: Failures: $failures"
exit $failures
