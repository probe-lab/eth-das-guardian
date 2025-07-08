BUILD_PATH := "./build"
BIN := "das-guardian"
GOCC := "go"
TARGET := "./cmd"

install:
    {{ GOCC }} install .

build:
    {{ GOCC }} build -o {{ BUILD_PATH }}/{{ BIN }} {{ TARGET }}

docker:
	docker build -t probe-lab/das-guardian:latest .

lint:
    staticcheck ./...

format:
    gofumpt -w -l .
