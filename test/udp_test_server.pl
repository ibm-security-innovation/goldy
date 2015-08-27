#!/usr/bin/env perl

use warnings;
use strict;
use Getopt::Std;
use IO::Socket;

$| = 1; # output autoflush

getopts("b:");
if (!$main::opt_b) {
    print "Usage: $0 -b <bind_address>\n";
    exit(1);
}

sub escape_char($) {
    my ($char) = @_;
    return "\\x" . unpack("H2", $char);
}

sub escape_string($) {
    my ($str) = @_;
    $str =~ s/[^\x20-\x7E]/escape_char($&)/ge;
    return $str;
}

my $MAXLEN = 10000;
my $bind_addr = $main::opt_b;
my $sock = IO::Socket::INET->new(LocalAddr => $bind_addr, Proto => 'udp') or die "socket bind failed: $@";
print "udp_test_server: Listening for UDP on $bind_addr\n";
my $packet;
while (my $peer = $sock->recv($packet, $MAXLEN, 0)) {
    my ($peerport, $peeripaddropaque) = unpack_sockaddr_in($peer);
    my $peeripaddr = inet_ntoa($peeripaddropaque);
    my $escaped_packet = escape_string($packet);
    print "udp_test_server: Received from $peeripaddr:$peerport - '$escaped_packet'\n";
    my $response = reverse($packet);
    $sock->send($response, 0, $peer);
    my $escaped_response = escape_string($response);
    print "udp_test_server:       Sent to $peeripaddr:$peerport - '$escaped_response'\n";
}
die "recv: $!";
