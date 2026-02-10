FROM golang:1.25 AS builder

WORKDIR /src
COPY go.mod ./
COPY *.go ./

RUN CGO_ENABLED=0 go build -o /vpcproxy .

FROM scratch

COPY --from=builder /vpcproxy /vpcproxy

EXPOSE 1080

ENTRYPOINT ["/vpcproxy"]
CMD ["-listen", "0.0.0.0:1080"]
