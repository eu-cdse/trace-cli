package main

import (
	"strings"
	"testing"
)

func expectEqual(expected any, actual any, t *testing.T) {
	if actual != expected {
		t.Fatalf("Results don't match. Expected '%v', Actual '%v'", expected, actual)
	}
}

func expectPrefix(expected_prefix string, actual string, t *testing.T) {
	if !strings.HasPrefix(actual, expected_prefix) {
		t.Fatalf("Results don't match. Expected prefix '%v', Actual '%v'", expected_prefix, actual)
	}
}

func TestCheckTraceUnsigned(t *testing.T) {
	trace := Trace{
		Product: Product{
			Hash: "abcd",
		},
		HashAlgorithm: "SHA256",
	}

	hash_bytes, _ := DecodeHash("abcd")
	status, message := ValidateTrace(&trace, hash_bytes, SHA256)
	expectEqual(true, status, t)
	expectPrefix("OK", message, t)
}

func TestCheckTraceSigned(t *testing.T) {
	private_key := DecodePrivateKey([]byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICXy35r0cy6uTDxIRQZZe/cqM8OwtxEWKcB3Xu1GXAXWoAoGCCqGSM49
AwEHoUQDQgAE0side0BK3IFRbv2c7Ay0jRxI8lg/bc3YjmFzCeiD89aVlLtyqrsh
HQwbNI9699O2uJopIg/zPGN/Yfixptbj5g==
-----END EC PRIVATE KEY-----
	`))
	product := Product{
		Hash: "abcd",
	}
	trace := Trace{
		Product:       product,
		HashAlgorithm: "SHA256",
		Signature:     CreateSignature(&product, private_key),
	}

	hash_bytes, _ := DecodeHash("abcd")
	status, message := ValidateTrace(&trace, hash_bytes, SHA256)
	expectEqual(true, status, t)
	expectEqual("OK", message, t)
}

func TestCheckTraceAlgorithmMismatch(t *testing.T) {
	trace := Trace{
		Product: Product{
			Hash: "abcd",
		},
		HashAlgorithm: "SHA256",
	}

	hash_bytes, _ := DecodeHash("abcd")
	status, message := ValidateTrace(&trace, hash_bytes, SHA3)
	expectEqual(false, status, t)
	expectPrefix("FAIL", message, t)
}

func TestCheckTraceChecksumMismatch(t *testing.T) {
	trace := Trace{
		Product: Product{
			Hash: "abcd",
		},
		HashAlgorithm: "SHA256",
	}

	hash_bytes, _ := DecodeHash("fefe")
	status, message := ValidateTrace(&trace, hash_bytes, SHA256)
	expectEqual(false, status, t)
	expectPrefix("FAIL", message, t)
}

func TestCheckTraceChecksumContent(t *testing.T) {
	trace := Trace{
		Product: Product{
			Hash: "abcd",
			Contents: &[]Content{
				Content{
					Hash: "affe",
					Path: "f123.nc",
				},
				Content{
					Hash: "fefe",
					Path: "f124.nc",
				},
			},
		},
		HashAlgorithm: "SHA256",
	}

	hash_bytes, _ := DecodeHash("fefe")
	status, message := ValidateTrace(&trace, hash_bytes, SHA256)
	expectPrefix("OK", message, t)
	expectEqual(true, status, t)
}
