
# yield branch or tag infromation
branch_tag := $(shell git symbolic-ref -q --short HEAD || git describe --tags --exact-match)
git_hash := $(shell git rev-parse --short HEAD)
version := ${branch_tag}-${git_hash}

standard_flags := -X main.version=${version}
compact_flags := -s -w ${standard_flags}

all: build test

test:
	go test -v ${test_args}

debug:
	go build -ldflags="${standard_flags}"

build:
	go build -ldflags="${compact_flags}"

release:
	GOOS=linux   GOARCH=amd64 go build -ldflags="${compact_flags}"
	GOOS=windows GOARCH=amd64 go build -ldflags="${compact_flags}"

.PHONY: all test build debug release
