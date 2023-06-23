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
	for i := range expected {
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
		Signature: CreateSignature(&RegisterTrace{Product: product},
			private_key, certificate),
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
				{
					Hash: "affe",
					Path: "f123.nc",
				},
				{
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

func TestTraceNameOverride(t *testing.T) {
	name := "asdf"
	traces := CreateProductTraces([]string{"test-data/test1.bin"}, &TraceTemplate{Name: &name}, BLAKE3, nil, nil)
	expectEqual(1, len(traces), t)
	expectEqual("asdf", traces[0].Product.Name, t)
}

func TestTraceNameDefault(t *testing.T) {
	name := ""
	traces := CreateProductTraces([]string{"test-data/test1.bin"}, &TraceTemplate{Name: &name}, BLAKE3, nil, nil)
	expectEqual(1, len(traces), t)
	expectEqual("test1.bin", traces[0].Product.Name, t)

	traces = CreateProductTraces([]string{"test-data/test1.bin"}, &TraceTemplate{}, BLAKE3, nil, nil)
	expectEqual(1, len(traces), t)
	expectEqual("test1.bin", traces[0].Product.Name, t)

}

func TestTraceNameOverrideIgnore(t *testing.T) {
	name := "asdf"
	traces := CreateProductTraces([]string{"test-data/test1.bin", "test-data/test2.bin"}, &TraceTemplate{Name: &name}, BLAKE3, nil, nil)
	expectEqual(2, len(traces), t)
	expectEqual("test1.bin", traces[0].Product.Name, t)
	expectEqual("test2.bin", traces[1].Product.Name, t)
}

func TestTraceHashOverride(t *testing.T) {
	hash := "0a0b0c0d"
	traces := CreateProductTraces([]string{""}, &TraceTemplate{Hash: &hash}, BLAKE3, nil, nil)
	expectEqual(1, len(traces), t)
	expectEqual("0a0b0c0d", traces[0].Product.Hash, t)
}

func TestTraceInputs(t *testing.T) {
	inputs := []Input{
		{
			Name: "abc",
			Hash: "010203",
		},
		{
			Name: "def",
			Hash: "040506",
		},
	}
	traces := CreateProductTraces([]string{"test-data/test1.bin", "test-data/test2.bin"}, &TraceTemplate{Inputs: &inputs}, BLAKE3, nil, nil)
	expectEqual(2, len(traces), t)
	// inputs are used for all products
	expectArrayEqual(inputs, *traces[0].Product.Inputs, t)
	expectArrayEqual(inputs, *traces[1].Product.Inputs, t)
}

func TestReadTraces(t *testing.T) {
	expected := CreateProductTraces([]string{"test-data/test1.bin"}, &TraceTemplate{}, BLAKE3, nil, nil)
	output := FormatTraces(&expected)
	actual, err := ReadProductTraces(strings.NewReader(output))
	ExpectNoErr(err, t)
	expectArrayEqual(expected, actual, t)
}

func TestReadTracesMulitple(t *testing.T) {
	input1 := CreateProductTraces([]string{"test-data/test1.bin"}, &TraceTemplate{}, BLAKE3, nil, nil)
	input2 := CreateProductTraces([]string{"test-data/test2.bin"}, &TraceTemplate{}, BLAKE3, nil, nil)

	var expected []RegisterTrace
	expected = append(expected, input1[:]...)
	expected = append(expected, input2[:]...)
	expectEqual(2, len(expected), t)

	output1 := FormatTraces(&input1)
	output2 := FormatTraces(&input2)

	actual, err := ReadProductTraces(strings.NewReader(output1), strings.NewReader(output2))
	ExpectNoErr(err, t)
	expectArrayEqual(expected, actual, t)
}

func TestSignatureTraceMatch(t *testing.T) {
	trace := Trace{
		Product: Product{
			Hash: "01020304",
			Name: "asdf",
			Size: 10023,
		},
	}

	message := string(CreateSignatureContents(&trace.Product, trace.Event))
	expectEqual(true, SignatureTraceMatch(&trace, message), t)
}

func TestSignatureTraceMatchContents(t *testing.T) {
	trace := Trace{
		Product: Product{
			Contents: &[]Content{
				{
					Path: "jkl/abc.de",
					Hash: "11121314",
				},
				{
					Path: "jkl/abc.ef",
					Hash: "15161718",
				},
			},
		},
	}

	message := string(CreateSignatureContents(&trace.Product, trace.Event))
	expectEqual(true, SignatureTraceMatch(&trace, message), t)

	message = `{
		"hash": "",
		"contents": [
			{"path": "jkl/abc.de", "hash": "11121314"},
			{"path": "jkl/abc.ef", "hash": "15161718"}
		]
		}`
	expectEqual(true, SignatureTraceMatch(&trace, message), t)

	message = `{
		"hash": "",
		"contents": []
		}`
	expectEqual(false, SignatureTraceMatch(&trace, message), t)
}

func TestSignatureTraceMatchInputs(t *testing.T) {
	trace := Trace{
		Product: Product{
			Inputs: &[]Input{
				{
					Name: "abc.de",
					Hash: "11121314",
				},
				{
					Name: "abc.ef",
					Hash: "15161718",
				},
			},
		},
	}

	message := string(CreateSignatureContents(&trace.Product, trace.Event))
	expectEqual(true, SignatureTraceMatch(&trace, message), t)

	message = `{
		"hash": "",
		"inputs": [
			{"name": "abc.de", "hash": "11121314"},
			{"name": "abc.ef", "hash": "15161718"}
		]
		}`
	expectEqual(true, SignatureTraceMatch(&trace, message), t)

	message = `{
		"hash": "",
		"inputs": []
		}`
	expectEqual(false, SignatureTraceMatch(&trace, message), t)
}

func TestSignatureTraceMatchApprox(t *testing.T) {
	trace := Trace{
		Product: Product{
			Hash: "01020304",
			Name: "asdf",
			Size: 10023,
		},
	}

	// no message = fail
	message := "{}"
	expectEqual(false, SignatureTraceMatch(&trace, message), t)

	// must have at least hash
	message = "{\"name\":\"asdf\"}"
	expectEqual(false, SignatureTraceMatch(&trace, message), t)
	message = "{\"hash\":\"01020304\"}"
	expectEqual(true, SignatureTraceMatch(&trace, message), t)

	// can have unneeded fields
	message = "{\"hash\":\"01020304\",\"other\":\"value\"}"
	expectEqual(true, SignatureTraceMatch(&trace, message), t)

	// order doesn't matter
	message = "{\"name\":\"asdf\",\"hash\":\"01020304\"}"
	expectEqual(true, SignatureTraceMatch(&trace, message), t)

	// if field present, it must match
	message = "{\"name\":\"jkl\",\"hash\":\"01020304\"}"
	expectEqual(false, SignatureTraceMatch(&trace, message), t)

	// check is case sensitive
	message = "{\"Hash\":\"01020304\"}"
	expectEqual(false, SignatureTraceMatch(&trace, message), t)
}
