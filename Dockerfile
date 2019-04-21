FROM alpine:3.9 as builder

RUN apk add --update build-base curl

WORKDIR /src

ADD . /src

RUN make deps && make

FROM alpine:3.9

COPY --from=builder /src/goldy /usr/local/bin/

ADD entrypoint.sh /

ENTRYPOINT ["/entrypoint.sh"]
