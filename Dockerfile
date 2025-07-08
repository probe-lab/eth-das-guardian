FROM golang:1.24 AS builder
RUN apt-get update && apt-get install -y ca-certificates
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -ldflags="-w -s" -o das-guardian ./cmd

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r appgroup && useradd -r -g appgroup appuser
WORKDIR /app
COPY --from=builder /app/das-guardian /app/das-guardian
RUN chmod +x /app/das-guardian && chown -R appuser:appgroup /app
USER appuser
EXPOSE 9013
ENTRYPOINT ["./das-guardian"]
CMD ["--help"]