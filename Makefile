
# yield branch or tag infromation
branch_tag := $(shell git symbolic-ref -q --short HEAD || git describe --tags --exact-match)
git_hash := $(shell git rev-parse --short HEAD)
version := ${branch_tag}-${git_hash}

standard_flags := -X main.version=${version}
compact_flags := -s -w ${standard_flags}

all: tidy build test

test:
	go test -v ${test_args}

debug:
	go build -ldflags="${standard_flags}"

build:
	go build -ldflags="${compact_flags}"

tidy:
	go fmt

regenerate:
	go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@latest
	oapi-codegen -generate types,client,spec -package main -o traceability.gen.go api-spec/cdas-traceability.json

release:
	GOOS=linux   GOARCH=amd64 go build -ldflags="${compact_flags}"
	GOOS=windows GOARCH=amd64 go build -ldflags="${compact_flags}"

.PHONY: all test debug build tidy regenerate release 
