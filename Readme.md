# CDAS Traceability Commandline Interface
This repository provides the comandline interface to generate, validate, and register traces for products managed by the Traceabiltiy Service of the Copernicus Data Access Service.

## Running the CLI
The general structure of the commandline tool follows the following pattern:
```
./trace-cli [OPTION...] COMMAND FILE...
```
The `COMMAND` defines the primary operation to be carried out, e.g. generating traces or checking products, while the `OPTION` configures general or command-specific settings. The eventual `FILE` refer to the products to which the command is applied on (.e.g. to check a number of products for consistency). The `help` command lists some example invocations.

The various commands options are shown when invoking the commandline tool without any extra arguments:
```
# Linux
./trace-cli

# Windows
trace-cli.exe
```

## Digital Signatures
All traces that are generated through the commandline tool can be signed digitally. Likewise, the tool will also verify digital signatures when checking a product's integrity.

How to use OpenSSL to generate a self-signed certificate:
```
# Generate a new set of e.g. RSA keys
openssl genrsa -out private.rsa.pem 4096

# Generate the corresponding certificate:
openssl req -x509 -sha256 -days 365 -key private.rsa.pem -out certificate.crt
```

How to use OpenSSL to validate trace signatures:
```
# Check the trace certificate
echo $trace.signature.public_key | base64 -d > trace.cer
openssl x509 -inform DER -in trace.cer -text -noout

# Dump the public key:
openssl x509 -inform DER -in trace.cer -noout -pubkey > trace-pubkey.pem

# Dump the signature bytes
echo $trace.signature.signature | base64 -d > data.sig

# Dump the content bytes
echo $trace.signature.message > data.txt

# Check the signature validaty, should print "Verified OK" on success
openssl dgst -sha256 -verify trace-pubkey.pem -signature data.sig data.txt

```
Note that depending on the signature algorithm used, `-sha256` needs to be adjusted. Important: this refers to the signature, not the product checksum algorithm.
Editors like Vim will add an EOL to text files, this needs to be either removed or STDIN used instead (CTRL-D to send EOF on unix).

How to use OpenSSL to create signatures:
```
# Create the signature
openssl dgst -sha256 -sign private.rsa.pem -out data.sig data.txt

# Encode the signature bytes
base64 -w 0 data.sig

# Encode the certificate
openssl x509 -inform PEM -in certificate.crt -outform DER -out certificate.cer
base64 -w 0 certificate.cer
```
Note that some signing algorithms (e.g. ECDSA) vary the signature each time it is generated, so don't expect byte equality.

## Building the CLI
In order to build the commandline tool either a golang build environment has to be setup, or it is built using docker/podman:
```
docker run --rm -it -v {$PWD}:/work/:Z -w /work/ golang:1.19.3 make
```

This will build the binary and run the tests. For additional build options, check the Makefile.

### Regenerating the OpenAPI endpoints
All the api-endpoint handling is automatically generated from the Traceabiltiy OpenAPI specification. In order to regenerate the endpoints use the `regenerate` target:
```
make regenerate
```

### Before release
```
go mod tidy
```
