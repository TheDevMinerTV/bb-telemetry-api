FROM golang:1.21.4 AS builder
WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o app

FROM alpine:3

COPY --from=builder /build/app /app

ENTRYPOINT ["/app", "-metrics-addr", ":65501", "-telemetry-addr", ":65500"]
