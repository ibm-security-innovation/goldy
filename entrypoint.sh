#!/bin/sh

GOLDY_ARGS=""

if [ -n "$CERT" ]; then
    echo $CERT | base64 -d > cert.crt
    GOLDY_ARGS="$GOLDY_ARGS -c cert.crt"
fi

if [ -n "$KEY" ]; then
    echo $KEY | base64 -d > key.pem
    GOLDY_ARGS="$GOLDY_ARGS -k key.pem"
fi

if [ -n "$LISTEN" ]; then
    GOLDY_ARGS="$GOLDY_ARGS -l $LISTEN"
fi

if [ -n "$BACKEND" ]; then
    GOLDY_ARGS="$GOLDY_ARGS -b $BACKEND"
fi

/usr/local/bin/goldy $GOLDY_ARGS $*
