#!/bin/sh

proxypid=
backendpid=
testdir=`dirname $0`
cd $testdir/..

kill_proxy() {
	echo "Killing proxy (PID $proxypid)"
	kill $proxypid
	wait $proxypid
	proxypid=
}

kill_backend() {
	echo "Killing backend test server (PID $backendpid)"
	kill $backendpid
	wait $backendpid
	backendpid=
}

cleanup() {
	if [ -n "$proxypid" ] ; then
		kill_proxy
	fi
	if [ -n "$backendpid" ] ; then
		kill_backend
	fi
	rm -f test/log/*.log
}


handle_signal() {
	cleanup
	exit 1
}

check_results() {
	actual_line=`grep 'bytes read' test/log/test_client.log`
	if [ -z "$actual_line" ] ; then
		echo "FAILED: No 'bytes read' in test_client.log"
		return
	fi

	expected_line="dtls_test_client: 22 bytes read: 'Something'"
	if [ "$actual_line" != "$expected_line" ] ; then
		echo "FAILED: Expected \"$expected_line\" but got \"$actual_line\""
		return
	fi
	echo "OK"
	retval=0
}

trap cleanup INT TERM HUP

echo "Starting proxy..."
./dtlsproxy > test/log/dtlsproxy.log &
proxypid=$!

echo "Starting test UDP backend server..."
test/udp_test_server.pl -b 127.0.0.1:29502 > test/log/test_server.log &
backendpid=$!

echo "Waiting for proxy and backend server to start..."
sleep 1

echo "Running test client..."
test/dtls_test_client > test/log/test_client.log

retval=1
echo "Checking results..."
check_results

echo "Done"

cleanup
exit $retval
