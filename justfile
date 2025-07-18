BUILD_PATH := "./build"
BIN := "das-guardian"
GOCC := "go"
TARGET := "./cmd"

install:
    {{ GOCC }} install .

build:
    {{ GOCC }} build -o {{ BUILD_PATH }}/{{ BIN }} {{ TARGET }}

lint:
    staticcheck ./...

format:
    gofumpt -w -l .

unit-test:
    {{ GOCC }} test -tags="!integration" $(go list ./... | grep -v ./cmd/)
