# CDAS Traceability Commandline Interface
This repository provides the comandline interface to generate, validate, and register traces for products managed by the Traceabiltiy Service of the Copernicus Data Access Service.

## Running the CLI
The general structure of the commandlien tool follows the following pattern:
```
./trace-cli [OPTION...] COMMAND FILE...
```
The `COMMAND` defines the primary operation to be carried out, e.g. generating traces or checking products, while the `OPTION` configures general or command-specific settings. The eventual `FILE` refer to the products to which the command is applied on (.e.g. to check a number of products for consistency). 

The various commands options are shown when invoking the commandline tool without any extra arguments:
```
~ ./trace-cli
```

## Building the CLI
In order to build the commandline tool either a golang build environment has to be setup, or it is built using docker/podman:
```
docker run --rm -it -v {$PWD}:/work/:Z -w /work/ golang:1.19.3 go build
```

Running the unit-tests:
```
docker run --rm -it -v {$PWD}:/work/:Z -w /work/ golang:1.19.3 go test -v
```

### Regenerating the OpenAPI endpoints
All the api-endpoint handling is automatically generated from the Traceabiltiy OpenAPI specification. In order to regenerate the endpoints use the following commands inside the build environment (e.g. container or native):
```
go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@latest
oapi-codegen -generate types,client,spec -package main -o traceability.gen.go api-spec/cdas-traceability.json
```

### Before commit
```
go fmt
go build
go test -v
```

### Before release
```
go mod tidy
```
