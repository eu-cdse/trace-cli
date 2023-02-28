# CDAS Traceability Commandline Interface
This repository provides the comandline interface to generate, validate, and register traces for products managed by the Traceabiltiy Service of the Copernicus Data Access Service.

## Running the CLI
The general structure of the commandline tool follows the following pattern:
```
./trace-cli [OPTION...] COMMAND FILE...
```
The `COMMAND` defines the primary operation to be carried out, e.g. generating traces or checking products, while the `OPTION` configures general or command-specific settings. The eventual `FILE` refer to the products to which the command is applied on (.e.g. to check a number of products for consistency). 

The various commands options are shown when invoking the commandline tool without any extra arguments:
```
~ ./trace-cli
```

## Digital Signatures
All traces that are generated through the commandline tool can be signed digitally. Likewise, the tool will also verify digital signatures when checking a products integrity.

Generate a new set of e.g. RSA keys:
```
openssl genrsa -out private.rsa.pem 4096
```

How to use OpenSSL to validate traces:
```
# Convert the public key into PEM format
echo $trace.signature.public_key > key.hex
xxd -plain -revert key.hex > key.der
openssl pkey -pubin -inform DER -in key.der -outform PEM -out key.pem

# Dump the signature bytes
echo $trace.signature.signature > data.sig.hex
xxd -plain -revert data.sig.hex > data.sig

# Dump the content bytes
echo <Trace-Content-No-EOL> > data.txt

# Check the signature validaty, should print "Verification OK" on success
openssl dgst -sha256 -verify key.pem -signature data.sig data.txt
```
Note that depending on the signature algorithm used, `-sha256` needs to be adjusted. Important: this refers to the signature, not the product checksum algorithm.
Editors like Vim will add an EOL to text files, this needs to be either removed or STDIN used instead (CTRL-D to send EOF on unix).

How to use OpenSSL to create signatures:
```
openssl dgst -sha256 -sign private.rsa.pem -out data.sig data.txt
```
Note that some signing algorithms (e.g. ECDSA) vary the signature ach time it's generated.

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
