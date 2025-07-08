FROM golang:1.24
RUN apt-get update && apt-get install -y ca-certificates && \
    groupadd -r appgroup && useradd -r -g appgroup appuser
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go clean -cache && go build -a -v -ldflags="-w -s" -o das-guardian ./cmd
RUN chmod +x das-guardian && chown -R appuser:appgroup /app
USER appuser
EXPOSE 9013
ENTRYPOINT ["./das-guardian"]
CMD ["--help"]