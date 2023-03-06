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
	private_key, err := DecodePrivateKey([]byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICXy35r0cy6uTDxIRQZZe/cqM8OwtxEWKcB3Xu1GXAXWoAoGCCqGSM49
AwEHoUQDQgAE0side0BK3IFRbv2c7Ay0jRxI8lg/bc3YjmFzCeiD89aVlLtyqrsh
HQwbNI9699O2uJopIg/zPGN/Yfixptbj5g==
-----END EC PRIVATE KEY-----
	`))
	ExpectNoErr(err, t, "Decoding private key: ")
	product := Product{
		Hash: "abcd",
	}
	trace := Trace{
		Product:       product,
		HashAlgorithm: "SHA256",
		Signature:     CreateSignature(&product, private_key),
	}

	hash_bytes, err := DecodeHash("abcd")
	ExpectNoErr(err, t, "Decoding Hash: ")
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

	hash_bytes, err := DecodeHash("abcd")
	ExpectNoErr(err, t, "Decoding Hash: ")
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

	hash_bytes, err := DecodeHash("fefe")
	ExpectNoErr(err, t, "Decoding Hash: ")
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

	hash_bytes, err := DecodeHash("fefe")
	ExpectNoErr(err, t, "Decoding Hash: ")
	status, message := ValidateTrace(&trace, hash_bytes, SHA256)
	expectPrefix("OK", message, t)
	expectEqual(true, status, t)
}

func TestTraceName(t *testing.T) {
	name := "asdf"
	traces := CreateProductTraces([]string{"test-data/test1.bin"}, &name, ValidateIncludePattern(""), COPY, nil)
	expectEqual(1, len(traces), t)
	expectEqual("asdf", traces[0].Product.Name, t)
}

func TestTraceNameDefault(t *testing.T) {
	name := ""
	traces := CreateProductTraces([]string{"test-data/test1.bin"}, &name, ValidateIncludePattern(""), COPY, nil)
	expectEqual(1, len(traces), t)
	expectEqual("test1.bin", traces[0].Product.Name, t)

	traces = CreateProductTraces([]string{"test-data/test1.bin"}, nil, ValidateIncludePattern(""), COPY, nil)
	expectEqual(1, len(traces), t)
	expectEqual("test1.bin", traces[0].Product.Name, t)

}

func TestTraceNameOverride(t *testing.T) {
	name := "asdf"
	traces := CreateProductTraces([]string{"test-data/test1.bin", "test-data/test2.bin"}, &name, ValidateIncludePattern(""), COPY, nil)
	expectEqual(2, len(traces), t)
	expectEqual("test1.bin", traces[0].Product.Name, t)
	expectEqual("test2.bin", traces[1].Product.Name, t)
}
