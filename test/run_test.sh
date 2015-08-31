#!/bin/sh

GOLDYHOST=127.0.0.1
GOLDYPORT=29501
BACKENDHOST=127.0.0.1
BACKENDPORT=29502

proxypid=
backendpid=
testdir=$(dirname $0)
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

test_one_packet() {
	packet=$1
	echo "Running test client with packet '$packet'..."
	test/dtls_test_client -n dtlsproxy.local -h $GOLDYHOST -p $GOLDYPORT -b "$packet" > test/log/test_client.log

	actual_line=$(grep 'bytes read' test/log/test_client.log)

	expected_packet=$(echo -n $packet | rev)
	expected_packet_len=${#expected_packet}
	expected_line="dtls_test_client: $expected_packet_len bytes read: '$expected_packet'"
	if [ "$actual_line" != "$expected_line" ] ; then
		echo "    FAILED: Expected \"$expected_line\" but got \"$actual_line\""
		return 1
	fi
	echo "    OK"
	return 0
}

trap handle_signal INT TERM HUP

echo "Starting proxy..."
./dtlsproxy -l $GOLDYHOST:$GOLDYPORT -b $BACKENDHOST:$BACKENDPORT -c test/keys/test-proxy-cert.pem -k test/keys/test-proxy-key.pem > test/log/dtlsproxy.log &
proxypid=$!

echo "Starting test UDP backend server..."
test/udp_test_server.pl -b $BACKENDHOST:$BACKENDPORT > test/log/test_server.log &
backendpid=$!

echo "Waiting for proxy and backend server to start..."
sleep 1

failures=0

test_one_packet "ABCD"
failures=$((failures+$?))

test_one_packet "Please reverse this message body"
failures=$((failures+$?))

test_one_packet "123456789012345678901234567890123456789012345678901234567890"
failures=$((failures+$?))

cleanup

echo "Done: Failures: $failures"
exit $failures
