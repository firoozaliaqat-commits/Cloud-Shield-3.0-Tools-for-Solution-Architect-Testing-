FROM alpine:3.21
RUN apk add --no-cache iperf3 && adduser -D -u 10003 netsim
USER netsim
ENTRYPOINT ["iperf3"]
CMD ["-s"]
