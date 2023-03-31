# The CDAS Traceability Commandline Interface utility.
# Copyright 2023 Cloudflight Austria GmbH

project := trace-cli

# yield branch or tag infromation
branch_tag := $(shell git symbolic-ref -q --short HEAD || git describe --tags --exact-match)
git_hash := $(shell git rev-parse --short HEAD)
version := ${branch_tag}-${git_hash}

standard_flags := -X main.version=${version}
compact_flags := -s -w ${standard_flags}

win32_target := ${project}_${branch_tag}_windows_amd64
linux_target := ${project}_${branch_tag}_linux_amd64

release_dir := release/

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
	GOOS=linux   GOARCH=amd64 go build -ldflags="${compact_flags}" -o "${release_dir}/${linux_target}/"
	GOOS=windows GOARCH=amd64 go build -ldflags="${compact_flags}" -o "${release_dir}/${win32_target}/"
	
	apt update -qq && apt install -qqy zip
	cp Readme.md "${release_dir}/${linux_target}/"
	cp Readme.md "${release_dir}/${win32_target}/"
	cd ${release_dir} && zip -r ${linux_target}.zip "${linux_target}"
	cd ${release_dir} && zip -r ${win32_target}.zip "${win32_target}"

.PHONY: all test debug build tidy regenerate release 
