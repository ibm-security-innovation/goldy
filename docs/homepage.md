# Goldy

## Overview

Goldy is a Datagram Transport Layer Security (DTLS) tunnel[^1].  It provides
encryption to clients and servers without the need to make changes to
underlying programs' code.

Goldy is similar in function to [stunnel](https://www.stunnel.org/) but works
over the User Datagram Protocol.  It proxies encrypted UDP communication to a
backend server, but it decrypts the communication on the way to the backend and
decrypts the backend responses on their way back to the client.

The backend usually runs on the same host as Goldy, making it ideal for
securely connecting backend services that can't communicate using DTLS with
clients that can.


![Goldy sequence diagram](goldy-diagram.png)


## What technology problem will I help solve?

You might have a device that understands DTLS; that is, it sends encrypted
communication over UDP.  But your server might not be aware of DTLS, and it
accepts plain UDP.  This is where Goldy proves its value.

Goldy will act as a tunnel, receiving encrypted DTLS communication, peeling off
that encryption and forwarding the plain content to a backend server.  The
server's replies are encrypted and sent to the client encrypted.  It relies on
mbedtls, an opensource SSL/TLS implementation by ARM, and libev, an
asynchronous events library.

Goldy requires a TLS certificate and its key to establish a secure channel.
This certificate must be trusted by Goldy's clients; if it is self-generated,
the clients should be configured accordingly, either by adding it to their
trusted list, or skipping the host verification altogether.  You can find
instructions for generating a self-signed certificate at mbedTLS or OpenSSL.

Goldy represents a simple way to secure your client/server interactions.  With
the certificate in place, all you need to do is to decide on a port to listen
to and whether you want Goldy to run as a daemon.  All you need is knowledge of
the backend address (usually localhost) and the port and you're ready to
encrypt your interactions.


## How will Goldy help my business?

Goldy is a lightweight, simple way to ensure secure communication between
client and server.  It saves you development time and costs; you can adapt it
for your own needs or contribute to its ongoing evolution. At a time when
security threats are omnipresent and growing, Goldy lets you implement secure
messaging quickly and easily.


[^1]: Note: this homepage was previously published on developer.ibm.com
