FROM golang:1.24 AS builder
RUN apt-get update && apt-get install -y git ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -ldflags="-w -s" -o /app/build/das-guardian .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates tzdata && rm -rf /var/lib/apt/lists/* && \
    groupadd -r appgroup && useradd -r -g appgroup appuser
WORKDIR /app
COPY --from=builder /app/build/das-guardian /app/das-guardian
RUN chown -R appuser:appgroup /app
USER appuser
EXPOSE 9013
ENTRYPOINT ["/app/das-guardian"]
CMD ["--help"]