FROM golang:1.26-alpine AS builder

ENV CGO_ENABLED=0

WORKDIR /app
RUN apk update --no-cache && \
    apk upgrade --no-cache && \
    apk add --no-cache make

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make

FROM alpine:3.21

RUN apk add --no-cache \
    chromium \
    ca-certificates

COPY --from=builder /app/yellow /usr/local/bin/yellow

WORKDIR /loot
ENTRYPOINT [ "/usr/local/bin/yellow" ]
