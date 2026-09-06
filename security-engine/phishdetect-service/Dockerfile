FROM golang:1.27-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libyara-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=1 go build \
    -tags netgo \
    -ldflags '-s -w' \
    -o phishdetect-service


FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libyara9 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/phishdetect-service .

EXPOSE 10000

CMD ["./phishdetect-service"]