FROM golang:1.23-alpine AS builder

WORKDIR /root
RUN apk update --no-cache && \
    apk upgrade --no-cache && \
    apk add --no-cache \
    make \
    build-base

COPY go.mod .
RUN go mod download

COPY . .
RUN make


FROM scratch

WORKDIR /app

COPY --from=builder /root/yellow .

ENTRYPOINT [ "/app/yellow" ]
