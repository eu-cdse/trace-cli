package main

import (
	"io"
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

func stringReader(str string) io.Reader {
	return strings.NewReader(str)
}

func TestSingleByteReader(t *testing.T) {
	data := strings.NewReader("asdfghjkl")

	rd := &SingleByteReader{data}

	arr := []byte{}
	n, err := rd.Read(arr)
	ExpectNoErr(err, t)
	expectEqual(0, n, t)

	arr = make([]byte, 10)
	n, err = rd.Read(arr)
	ExpectNoErr(err, t)
	expectEqual(1, n, t)
	expectEqual(arr[0], 'a', t)

	n, err = rd.Read(arr)
	ExpectNoErr(err, t)
	expectEqual(1, n, t)
	expectEqual(arr[0], 's', t)

	// empty raw reader
	n, err = data.Read(arr)
	ExpectNoErr(err, t)
	expectEqual(7, n, t)

	n, err = rd.Read(arr)
	expectEqual(0, n, t)
	if err == nil {
		t.Fatalf("expected error at end, but got '%v'", err)
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
MIIBtTCCAVugAwIBAgIUPTz++ju3aQVfrVBgSgZEIFlzn5YwCgYIKoZIzj0EAwIw
MDELMAkGA1UEBhMCQVQxITAfBgNVBAoMGENsb3VkZmxpZ2h0IEF1c3RyaWEgR21i
SDAeFw0yNDA4MTIxNTE4MjVaFw0zNDA4MTAxNTE4MjVaMDAxCzAJBgNVBAYTAkFU
MSEwHwYDVQQKDBhDbG91ZGZsaWdodCBBdXN0cmlhIEdtYkgwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAATSyJ17QErcgVFu/ZzsDLSNHEjyWD9tzdiOYXMJ6IPz1pWU
u3KquyEdDBs0j3r307a4mikiD/M8Y39h+LGm1uPmo1MwUTAdBgNVHQ4EFgQUqrYq
mOxP+5k6+fS4tOZzDzDZVdowHwYDVR0jBBgwFoAUqrYqmOxP+5k6+fS4tOZzDzDZ
VdowDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAzH20lo3vQdVj
MHAB++WSVF0IffqX9lpCEdoukju2kHYCIEhYXCufDjiyFVTLijJtbeXpZMqjxjJR
aO/AMbv1tUAL
-----END CERTIFICATE-----	
	`), time.Now())
	ExpectNoErr(err, t, "Decoding certificate: ")

	product := Product{
		Hash: "abcd",
	}
	trace := Trace{
		Product:       product,
		HashAlgorithm: "SHA256",
		Timestamp:     time.Date(2024, time.September, 1, 0, 0, 0, 0, time.UTC), // must be within certificate range
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

func TestCheckAndPrintTraces(t *testing.T) {
	traces := []Trace{
		{
			Product: Product{
				Hash: "abcd",
			},
			HashAlgorithm: "SHA256",
			Event:         CREATE,
		},
		{
			Product: Product{
				Hash: "cdef",
			},
			HashAlgorithm: "SHA256",
			Event:         CREATE,
		},
		{
			Product: Product{
				Hash: "cdab",
			},
			HashAlgorithm: "BLAKE3",
			Event:         CREATE,
		},
	}
	hash_bytes, err := DecodeHash("abcd")
	ExpectNoErr(err, t, "Decoding Hash: ")
	expectEqual(true, checkAndPrintTraces(&traces, hash_bytes, SHA256), t) // ok

	hash_bytes, err = DecodeHash("abef")
	ExpectNoErr(err, t, "Decoding Hash: ")
	expectEqual(false, checkAndPrintTraces(&traces, hash_bytes, SHA256), t) // wrong checksum

	hash_bytes, err = DecodeHash("cdab")
	ExpectNoErr(err, t, "Decoding Hash: ")
	expectEqual(false, checkAndPrintTraces(&traces, hash_bytes, SHA256), t) // wrong alg
}

func TestCheckAndPrintTracesObsolete(t *testing.T) {
	traces := []Trace{
		{
			Product: Product{
				Hash: "abcd",
			},
			HashAlgorithm: "SHA256",
			Event:         CREATE,
		},
		{
			Product: Product{
				Hash: "abcd",
			},
			HashAlgorithm: "SHA256",
			Event:         OBSOLETE,
		},
	}
	hash_bytes, err := DecodeHash("abcd")
	ExpectNoErr(err, t, "Decoding Hash: ")
	expectEqual(false, checkAndPrintTraces(&traces, hash_bytes, SHA256), t) // fail because obsolete
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
	expected := CreateProductTraces([]string{"test-data/test1.bin", "test-data/test2.bin"}, &TraceTemplate{}, BLAKE3, nil, nil)
	output := FormatTraces(&expected)
	actual, err := ReadProductTraces(stringReader(output))
	ExpectNoErr(err, t)
	expectEqual(2, len(actual), t)
	expectArrayEqual(expected, actual, t)
}

func TestReadTracesMultipleReader(t *testing.T) {
	input1 := CreateProductTraces([]string{"test-data/test1.bin"}, &TraceTemplate{}, BLAKE3, nil, nil)
	input2 := CreateProductTraces([]string{"test-data/test2.bin"}, &TraceTemplate{}, BLAKE3, nil, nil)

	var expected []RegisterTrace
	expected = append(expected, input1[:]...)
	expected = append(expected, input2[:]...)
	expectEqual(2, len(expected), t)

	output1 := FormatTraces(&input1)
	output2 := FormatTraces(&input2)

	actual, err := ReadProductTraces(stringReader(output1), stringReader(output2))
	ExpectNoErr(err, t)
	expectArrayEqual(expected, actual, t)
}

func TestReadTracesSubsequently(t *testing.T) {
	expected1 := CreateProductTraces([]string{"test-data/test1.bin"}, &TraceTemplate{}, BLAKE3, nil, nil)
	expected2 := CreateProductTraces([]string{"test-data/test2.bin"}, &TraceTemplate{}, BLAKE3, nil, nil)

	output := FormatTraces(&expected1) + FormatTraces(&expected2)
	reader := stringReader(output)

	actual1, err := ReadProductTraces(reader)
	ExpectNoErr(err, t)

	actual2, err := ReadProductTraces(reader)
	ExpectNoErr(err, t)

	_, err = ReadProductTraces(reader)
	if err == nil {
		t.Errorf("Expected error, but got '%v'", err)
	}

	expectArrayEqual(expected1, actual1, t)
	expectArrayEqual(expected2, actual2, t)
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
		"hash": "", "event": "",
		"contents": [
			{"path": "jkl/abc.de", "hash": "11121314"},
			{"path": "jkl/abc.ef", "hash": "15161718"}
		]
		}`
	expectEqual(true, SignatureTraceMatch(&trace, message), t)

	message = `{
		"hash": "", "event": "",
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
		"hash": "", "event": "",
		"inputs": [
			{"name": "abc.de", "hash": "11121314"},
			{"name": "abc.ef", "hash": "15161718"}
		]
		}`
	expectEqual(true, SignatureTraceMatch(&trace, message), t)

	message = `{
		"hash": "", "event": "",
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
		Event: COPY,
	}

	// no message = fail
	message := "{}"
	expectEqual(false, SignatureTraceMatch(&trace, message), t)

	// must have at least hash and event
	message = "{\"name\":\"asdf\"}"
	expectEqual(false, SignatureTraceMatch(&trace, message), t)
	message = "{\"hash\":\"01020304\"}"
	expectEqual(false, SignatureTraceMatch(&trace, message), t)
	message = "{\"event\":\"COPY\"}"
	expectEqual(false, SignatureTraceMatch(&trace, message), t)
	message = "{\"hash\":\"01020304\",\"event\":\"COPY\"}"
	expectEqual(true, SignatureTraceMatch(&trace, message), t)

	// can have unneeded fields
	message = "{\"hash\":\"01020304\",\"event\":\"COPY\",\"other\":\"value\"}"
	expectEqual(true, SignatureTraceMatch(&trace, message), t)

	// order doesn't matter
	message = "{\"name\":\"asdf\",\"hash\":\"01020304\",\"event\":\"COPY\"}"
	expectEqual(true, SignatureTraceMatch(&trace, message), t)

	// if field present, it must match
	message = "{\"name\":\"jkl\",\"hash\":\"01020304\",\"event\":\"COPY\"}"
	expectEqual(false, SignatureTraceMatch(&trace, message), t)

	// check is case sensitive
	message = "{\"Hash\":\"01020304\"},\"event\":\"COPY\""
	expectEqual(false, SignatureTraceMatch(&trace, message), t)
}

func TestUpdateTrace(t *testing.T) {
	traces := []RegisterTrace{{
		Product: Product{
			Name: "asdf",
		},
		Event: CREATE,
	}}
	expected := []RegisterTrace{{
		Product: Product{
			Name: "jkl",
		},
		Event: CREATE,
	}}
	name := "jkl"
	UpdateTraces(&traces, &TraceTemplate{Name: &name}, nil, nil)
	expectArrayEqual(expected, traces, t)
}

func TestUpdateTraceMultiple(t *testing.T) {

	traces := []RegisterTrace{{
		Product: Product{
			Name: "asdf",
		},
		Event: CREATE,
	}, {
		Product: Product{
			Name: "jkl",
		},
		Event: CREATE,
	}}
	expected := []RegisterTrace{{
		Product: Product{
			Name: "asdf",
		},
		Event: COPY,
	}, {
		Product: Product{
			Name: "jkl",
		},
		Event: COPY,
	}}
	UpdateTraces(&traces, &TraceTemplate{Event: COPY}, nil, nil)
	expectArrayEqual(expected, traces, t)
}

func TestUpdateTraceNoChanges(t *testing.T) {
	traces := []RegisterTrace{{
		Product: Product{
			Name: "asdf",
		},
		Event: CREATE,
		Signature: Signature{
			Message: "qwert",
		},
	}}
	expected := []RegisterTrace{{
		Product: Product{
			Name: "asdf",
		},
		Event: CREATE,
		Signature: Signature{
			Message: "qwert",
		},
	}}
	UpdateTraces(&traces, &TraceTemplate{}, nil, nil)
	expectArrayEqual(expected, traces, t)
}

func TestUpdateTraceObsolescense(t *testing.T) {
	obsmsg := "outdated"
	name := "jkl"

	traces := []RegisterTrace{{
		Product: Product{
			Name: "asdf",
		},
		Event:        OBSOLETE,
		Obsolescence: &obsmsg,
	}}

	reset := []RegisterTrace{{
		Product: Product{
			Name: "jkl",
		},
		Event: COPY,
	}}
	UpdateTraces(&traces, &TraceTemplate{Name: &name, Event: COPY}, nil, nil)
	expectArrayEqual(reset, traces, t)

	added := []RegisterTrace{{
		Product: Product{
			Name: "jkl",
		},
		Event:        OBSOLETE,
		Obsolescence: &obsmsg,
	}}
	UpdateTraces(&traces, &TraceTemplate{Name: &name, Event: OBSOLETE, Obsolescence: &obsmsg}, nil, nil)
	expectArrayEqual(added, traces, t)
}

func TestUpdateTraceSignature(t *testing.T) {
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
MIIBtTCCAVugAwIBAgIUPTz++ju3aQVfrVBgSgZEIFlzn5YwCgYIKoZIzj0EAwIw
MDELMAkGA1UEBhMCQVQxITAfBgNVBAoMGENsb3VkZmxpZ2h0IEF1c3RyaWEgR21i
SDAeFw0yNDA4MTIxNTE4MjVaFw0zNDA4MTAxNTE4MjVaMDAxCzAJBgNVBAYTAkFU
MSEwHwYDVQQKDBhDbG91ZGZsaWdodCBBdXN0cmlhIEdtYkgwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAATSyJ17QErcgVFu/ZzsDLSNHEjyWD9tzdiOYXMJ6IPz1pWU
u3KquyEdDBs0j3r307a4mikiD/M8Y39h+LGm1uPmo1MwUTAdBgNVHQ4EFgQUqrYq
mOxP+5k6+fS4tOZzDzDZVdowHwYDVR0jBBgwFoAUqrYqmOxP+5k6+fS4tOZzDzDZ
VdowDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAzH20lo3vQdVj
MHAB++WSVF0IffqX9lpCEdoukju2kHYCIEhYXCufDjiyFVTLijJtbeXpZMqjxjJR
aO/AMbv1tUAL
-----END CERTIFICATE-----	
	`), time.Now())
	ExpectNoErr(err, t, "Decoding certificate: ")

	traces := []RegisterTrace{{
		Product: Product{
			Name: "asdf",
		},
		Event: CREATE,
	}}

	name := "jkl"
	UpdateTraces(&traces, &TraceTemplate{Name: &name, Event: COPY}, private_key, certificate)

	expected := Trace{
		Product: Product{
			Name: "jkl",
		},
		Event: COPY,
	}
	status := SignatureTraceMatch(&expected, traces[0].Signature.Message)
	expectEqual(true, status, t)
}

func TestUpdateTraceSignatureReset(t *testing.T) {
	traces := []RegisterTrace{{
		Product: Product{
			Name: "asdf",
		},
		Event: CREATE,
		Signature: Signature{
			Message: "qwert",
		},
	}}
	expected := []RegisterTrace{{
		Product: Product{
			Name: "jkl",
		},
		Event: CREATE,
	}}
	name := "jkl"
	UpdateTraces(&traces, &TraceTemplate{Name: &name}, nil, nil)
	expectArrayEqual(expected, traces, t)
}
