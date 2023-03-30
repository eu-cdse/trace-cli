package main

import (
	"strings"
	"testing"
	"time"
)

func expectEqual[T comparable](expected T, actual T, t *testing.T) {
	if actual != expected {
		t.Fatalf("Results don't match. Expected '%v', Actual '%v'", expected, actual)
	}
}
func expectArrayEqual[T comparable](expected []T, actual []T, t *testing.T) {
	if len(actual) != len(expected) {
		t.Fatalf("Results don't match. Expected '%v', Actual '%v'", expected, actual)
	}
	for i, _ := range expected {
		if actual[i] != expected[i] {
			t.Fatalf("Results don't match. Expected '%v', Actual '%v'", expected, actual)
		}
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
	certificate, err := DecodeCertificatePEM([]byte(`
-----BEGIN CERTIFICATE-----
MIIB3zCCAYWgAwIBAgIUM79G6XVXCF4OgceWfI8TW6tlLw4wCgYIKoZIzj0EAwIw
RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzAzMTAyMTQyNDZaFw0yNDAzMDky
MTQyNDZaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD
VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATSyJ17QErcgVFu/ZzsDLSNHEjyWD9tzdiOYXMJ6IPz1pWUu3KquyEd
DBs0j3r307a4mikiD/M8Y39h+LGm1uPmo1MwUTAdBgNVHQ4EFgQUqrYqmOxP+5k6
+fS4tOZzDzDZVdowHwYDVR0jBBgwFoAUqrYqmOxP+5k6+fS4tOZzDzDZVdowDwYD
VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAw9U3hqAjka7v/Ef1RpQF
iDJ7shMbFZyoqIsmPKlm1zUCIFgFkahzLWnLZxCCLPSecCPMWzsV6MRk+F4IzMFY
ug2G
-----END CERTIFICATE-----	
	`), time.Now())
	ExpectNoErr(err, t, "Decoding certificate: ")

	product := Product{
		Hash: "abcd",
	}
	trace := Trace{
		Product:       product,
		HashAlgorithm: "SHA256",
		Signature:     CreateSignature(&product, private_key, certificate),
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
	traces := CreateProductTraces([]string{"test-data/test1.bin"}, &name, ValidateIncludePattern(""), nil, COPY, nil, nil, nil)
	expectEqual(1, len(traces), t)
	expectEqual("asdf", traces[0].Product.Name, t)
}

func TestTraceNameDefault(t *testing.T) {
	name := ""
	traces := CreateProductTraces([]string{"test-data/test1.bin"}, &name, ValidateIncludePattern(""), nil, COPY, nil, nil, nil)
	expectEqual(1, len(traces), t)
	expectEqual("test1.bin", traces[0].Product.Name, t)

	traces = CreateProductTraces([]string{"test-data/test1.bin"}, nil, ValidateIncludePattern(""), nil, COPY, nil, nil, nil)
	expectEqual(1, len(traces), t)
	expectEqual("test1.bin", traces[0].Product.Name, t)

}

func TestTraceNameOverride(t *testing.T) {
	name := "asdf"
	traces := CreateProductTraces([]string{"test-data/test1.bin", "test-data/test2.bin"}, &name, ValidateIncludePattern(""), nil, COPY, nil, nil, nil)
	expectEqual(2, len(traces), t)
	expectEqual("test1.bin", traces[0].Product.Name, t)
	expectEqual("test2.bin", traces[1].Product.Name, t)
}

func TestTraceInputs(t *testing.T) {
	inputs := []Input{
		Input{
			Name: "abc",
			Hash: "010203",
		},
		Input{
			Name: "def",
			Hash: "040506",
		},
	}
	traces := CreateProductTraces([]string{"test-data/test1.bin", "test-data/test2.bin"}, nil, ValidateIncludePattern(""),
		&inputs, COPY, nil, nil, nil)
	expectEqual(2, len(traces), t)
	// inputs are used for all products
	expectArrayEqual(inputs, *traces[0].Product.Inputs, t)
	expectArrayEqual(inputs, *traces[1].Product.Inputs, t)
}
