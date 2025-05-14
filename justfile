BUILD_PATH := "./build"
BIN := "das-guardian"
GOCC := "go"

install:
    {{GOCC}} install .

build:
    {{GOCC}} build -o {{BUILD_PATH}}/{{BIN}} .

lint:
    staticcheck ./...

format:
    gofumpt -w -l .
