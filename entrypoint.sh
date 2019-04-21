#!/bin/sh

[ -n "$CERT" ] && [ -n "$CERT_FILENAME" ] && echo $CERT | base64 -d > $CERT_FILENAME
[ -n "$KEY" ] && [ -n "$KEY_FILENAME" ] && echo $KEY | base64 -d > $KEY_FILENAME

/usr/local/bin/goldy $*
