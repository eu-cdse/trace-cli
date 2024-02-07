package main

import (
	"math/big"
	"strings"
	"testing"
	"time"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
)

func ExpectNoErr(err error, t *testing.T, message ...string) {
	if err != nil {
		t.Errorf("%sExpected no error, but got %v", strings.Join(message, " "), err)
	}
}

func TestDecodePrivateKeyRSA(t *testing.T) {
	pemfile := `
-----BEGIN RSA PRIVATE KEY-----
MIIBPAIBAAJBAN97tKREG2eUEf/DviHqi1WeVYwDrj9Mph6yGhOcybfjDC5vioru
LEE3izAK/WV0HllgL0/SY6lwAo3JbiTRGh0CAwEAAQJBAJnR13/IsOQV8l2MKO3H
Naf0lwUL8372DtDJ3VDqdZzui+KfrTjA6ro0V1AGbs7Yd1YrJJk9G97/wCvtLO5r
x4ECIQD7coUOPPOdIm2NgSbrkDuvgDi35Pa5LKFTiHoXDZHxmQIhAOOHkdyIMeJw
LXssMN+/P/rmIAcLgP3YYrjaJcUIzgclAiEA2Q8M6TOYoSbdJ3A8JtGFlIS9cZHH
oiZyxWdk7Y2bVNECIDg/Bk7XGEXa51NgrEBTnfRfOSGktWGLQXRi8R1RPOVFAiEA
hq3voIKDTqDt1s8fd+p5DntwxoEaJN3OuLphnFNzkmY=
-----END RSA PRIVATE KEY-----	
	`
	_, err := DecodePrivateKey([]byte(pemfile))
	ExpectNoErr(err, t, "Decoding private key: ")
}

func TestDecodePrivateKeyEC(t *testing.T) {
	pemfile := `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICXy35r0cy6uTDxIRQZZe/cqM8OwtxEWKcB3Xu1GXAXWoAoGCCqGSM49
AwEHoUQDQgAE0side0BK3IFRbv2c7Ay0jRxI8lg/bc3YjmFzCeiD89aVlLtyqrsh
HQwbNI9699O2uJopIg/zPGN/Yfixptbj5g==
-----END EC PRIVATE KEY-----
	`
	_, err := DecodePrivateKey([]byte(pemfile))
	ExpectNoErr(err, t, "Decoding private key: ")
}

func TestDecodePrivateKeyPK8(t *testing.T) {
	pemfile := `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJfLfmvRzLq5MPEhF
Bll79yozw7C3ERYpwHde7UZcBdahRANCAATSyJ17QErcgVFu/ZzsDLSNHEjyWD9t
zdiOYXMJ6IPz1pWUu3KquyEdDBs0j3r307a4mikiD/M8Y39h+LGm1uPm
-----END PRIVATE KEY-----	
	`
	_, err := DecodePrivateKey([]byte(pemfile))
	ExpectNoErr(err, t, "Decoding private key: ")
}

func TestDecodePrivateKeyPassword(t *testing.T) {
	pemfile := `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAipQ9l2t1LjCQICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEDtA5jlHoM00io8FjBCxFb8EgZCT
D7uRRiukUhZFQY78T+2ZUNZEyrkr+BOOq4HJ+cvjSOkboOZqo/A7Qk9oKxiOmybc
Ch//nM3xlDNXTWatDiWIMl1UgfYZr5mmuZwapFhh/4tOTRc4jUPEdHwCLXeHyfu9
ngdLdL7SUBqcJSbvt2zXUhBE2R5do1QwDHzXsqWf/MGNOytPQAB8ZiQ2Gzg+zlE=
-----END ENCRYPTED PRIVATE KEY-----
`
	_, err := DecodePrivateKey([]byte(pemfile), func() string {
		return "abc123"
	})
	ExpectNoErr(err, t, "Decoding private key: ")

}

// Currently not possible due to bug in library, issue #...
// func TestDecodePrivateKeyEmptyPassword(t *testing.T) {
// 	pemfile := `
// -----BEGIN ENCRYPTED PRIVATE KEY-----
// MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAhCXnbnxWsdAAICCAAw
// DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEECd1dzLmsj4/XsSvPetvoN4EgZCJ
// HUEnIFQC8hXJ8XuGknXviDvEBwShLKDmLzhZaGgy9ec/xB7IhkgRrdDi6xy2wjGQ
// oX7xV/iLSQvusg7YNmnixFOTlvIddbdmE23IQ874GHyFOyKCjmTwOEbj6VUXjbdH
// q8DMkCAbsuc0a3nK+Qmy50IQso9bve2ZDTcCD1jCVT+hy9AohXgn6p5soqroeuc=
// -----END ENCRYPTED PRIVATE KEY-----
// `
// _, err := DecodePrivateKey([]byte(pemfile))
// ExpectNoErr(err, t, "Decoding private key: ")
// }

func TestDecodePublicKeyRSA(t *testing.T) {
	key_hex := "305c300d06092a864886f70d0101010500034b003048024100df7bb4a4441b679411ffc3be21ea8b559e558c03ae3f4ca61eb21a139cc9b7e30c2e6f8a8aee2c41378b300afd65741e59602f4fd263a970028dc96e24d11a1d0203010001"
	bytes, err := DecodeHash(key_hex)
	ExpectNoErr(err, t, "Decoding Hash: ")
	_, err = DecodePublicKey(bytes)
	ExpectNoErr(err, t, "Unable to parse key: ")
}

func TestDecodePublicKeyECDSA(t *testing.T) {
	key_hex := "3059301306072a8648ce3d020106082a8648ce3d03010703420004d2c89d7b404adc81516efd9cec0cb48d1c48f2583f6dcdd88e617309e883f3d69594bb72aabb211d0c1b348f7af7d3b6b89a29220ff33c637f61f8b1a6d6e3e6"
	bytes, err := DecodeHash(key_hex)
	ExpectNoErr(err, t, "Decoding Hash: ")
	_, err = DecodePublicKey(bytes)
	ExpectNoErr(err, t, "Unable to parse key: ")
}

func TestDecodeCertificatePEM(t *testing.T) {
	cert, err := DecodeCertificatePEM([]byte(`
-----BEGIN CERTIFICATE-----
MIIB4TCCAYugAwIBAgIUNXehXpBXahTamrUu5HNAv85FJyAwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzAzMTAyMTQxMjhaFw0yNDAz
MDkyMTQxMjhaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwXDANBgkqhkiG9w0BAQEF
AANLADBIAkEA33u0pEQbZ5QR/8O+IeqLVZ5VjAOuP0ymHrIaE5zJt+MMLm+Kiu4s
QTeLMAr9ZXQeWWAvT9JjqXACjcluJNEaHQIDAQABo1MwUTAdBgNVHQ4EFgQUjApm
pYWiYWEHj45zDS4fvw+3c2EwHwYDVR0jBBgwFoAUjApmpYWiYWEHj45zDS4fvw+3
c2EwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAANBAHgaTvPXpWIn4L1R
IMrJuXYdUSmXklMqMYlq3in7JG1wyEpyXycZcIxdkidNpvTVxx3nyaqwiGMSih66
6VQu1y8=
-----END CERTIFICATE-----	
	`), time.Now())
	ExpectNoErr(err, t)
	expectEqual(x509.SHA256WithRSA, cert.SignatureAlgorithm, t)
}

func TestDecodeCertificateDER(t *testing.T) {
	cert_hex := "308201df30820185a003020102021433bf46e97557085e0e81c7967c8f135bab652f0e300a06082a8648ce3d0403023045310b30090603550406130241553113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c7464301e170d3233303331303231343234365a170d3234303330393231343234365a3045310b30090603550406130241553113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c74643059301306072a8648ce3d020106082a8648ce3d03010703420004d2c89d7b404adc81516efd9cec0cb48d1c48f2583f6dcdd88e617309e883f3d69594bb72aabb211d0c1b348f7af7d3b6b89a29220ff33c637f61f8b1a6d6e3e6a3533051301d0603551d0e04160414aab62a98ec4ffb993af9f4b8b4e6730f30d955da301f0603551d23041830168014aab62a98ec4ffb993af9f4b8b4e6730f30d955da300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022100c3d53786a02391aeeffc47f546940588327bb2131b159ca8a88b263ca966d7350220580591a8732d69cb6710822cf49e7023cc5b3b15e8c464f85e08ccc158ba0d86"
	bytes, err := DecodeHash(cert_hex)
	ExpectNoErr(err, t, "Decoding Hash: ")
	cert, err := DecodeCertificateDER(bytes, time.Now())
	ExpectNoErr(err, t)
	expectEqual(x509.ECDSAWithSHA256, cert.SignatureAlgorithm, t)
}

func TestSignVerifyRSA(t *testing.T) {
	text := strings.Repeat("abc123", 100)
	private_key, err := DecodePrivateKey([]byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIBPAIBAAJBAN97tKREG2eUEf/DviHqi1WeVYwDrj9Mph6yGhOcybfjDC5vioru
LEE3izAK/WV0HllgL0/SY6lwAo3JbiTRGh0CAwEAAQJBAJnR13/IsOQV8l2MKO3H
Naf0lwUL8372DtDJ3VDqdZzui+KfrTjA6ro0V1AGbs7Yd1YrJJk9G97/wCvtLO5r
x4ECIQD7coUOPPOdIm2NgSbrkDuvgDi35Pa5LKFTiHoXDZHxmQIhAOOHkdyIMeJw
LXssMN+/P/rmIAcLgP3YYrjaJcUIzgclAiEA2Q8M6TOYoSbdJ3A8JtGFlIS9cZHH
oiZyxWdk7Y2bVNECIDg/Bk7XGEXa51NgrEBTnfRfOSGktWGLQXRi8R1RPOVFAiEA
hq3voIKDTqDt1s8fd+p5DntwxoEaJN3OuLphnFNzkmY=
-----END RSA PRIVATE KEY-----
	`))
	ExpectNoErr(err, t)
	cert, err := DecodeCertificatePEM([]byte(`
-----BEGIN CERTIFICATE-----
MIIB4TCCAYugAwIBAgIUNXehXpBXahTamrUu5HNAv85FJyAwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzAzMTAyMTQxMjhaFw0yNDAz
MDkyMTQxMjhaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwXDANBgkqhkiG9w0BAQEF
AANLADBIAkEA33u0pEQbZ5QR/8O+IeqLVZ5VjAOuP0ymHrIaE5zJt+MMLm+Kiu4s
QTeLMAr9ZXQeWWAvT9JjqXACjcluJNEaHQIDAQABo1MwUTAdBgNVHQ4EFgQUjApm
pYWiYWEHj45zDS4fvw+3c2EwHwYDVR0jBBgwFoAUjApmpYWiYWEHj45zDS4fvw+3
c2EwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAANBAHgaTvPXpWIn4L1R
IMrJuXYdUSmXklMqMYlq3in7JG1wyEpyXycZcIxdkidNpvTVxx3nyaqwiGMSih66
6VQu1y8=
-----END CERTIFICATE-----	
	`), time.Now())
	ExpectNoErr(err, t)

	algorithm, signature, cert_bytes := Sign([]byte(text), private_key, cert)

	if algorithm != "RSA-SHA256" {
		t.Errorf("Signature algorithm unexpected: %s", algorithm)
	}

	valid := VerifySignature([]byte(text), signature, cert_bytes, algorithm, time.Now())

	if !valid {
		t.Fatalf("Signature validation failed.")
	}
}

func TestSignVerifyEC(t *testing.T) {
	text := strings.Repeat("abc123", 100)
	private_key, err := DecodePrivateKey([]byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICXy35r0cy6uTDxIRQZZe/cqM8OwtxEWKcB3Xu1GXAXWoAoGCCqGSM49
AwEHoUQDQgAE0side0BK3IFRbv2c7Ay0jRxI8lg/bc3YjmFzCeiD89aVlLtyqrsh
HQwbNI9699O2uJopIg/zPGN/Yfixptbj5g==
-----END EC PRIVATE KEY-----
	`))
	ExpectNoErr(err, t)
	cert, err := DecodeCertificatePEM([]byte(`
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
	ExpectNoErr(err, t)

	algorithm, signature, cert_bytes := Sign([]byte(text), private_key, cert)

	if algorithm != "ECDSA-SHA256" {
		t.Errorf("Signature algorithm unexpected: %s", algorithm)
	}

	valid := VerifySignature([]byte(text), signature, cert_bytes, algorithm, time.Now())

	if !valid {
		t.Fatalf("Signature validation failed.")
	}
}

func TestSignRSARaw(t *testing.T) {
	key, err := DecodePrivateKey([]byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIBPAIBAAJBAN97tKREG2eUEf/DviHqi1WeVYwDrj9Mph6yGhOcybfjDC5vioru
LEE3izAK/WV0HllgL0/SY6lwAo3JbiTRGh0CAwEAAQJBAJnR13/IsOQV8l2MKO3H
Naf0lwUL8372DtDJ3VDqdZzui+KfrTjA6ro0V1AGbs7Yd1YrJJk9G97/wCvtLO5r
x4ECIQD7coUOPPOdIm2NgSbrkDuvgDi35Pa5LKFTiHoXDZHxmQIhAOOHkdyIMeJw
LXssMN+/P/rmIAcLgP3YYrjaJcUIzgclAiEA2Q8M6TOYoSbdJ3A8JtGFlIS9cZHH
oiZyxWdk7Y2bVNECIDg/Bk7XGEXa51NgrEBTnfRfOSGktWGLQXRi8R1RPOVFAiEA
hq3voIKDTqDt1s8fd+p5DntwxoEaJN3OuLphnFNzkmY=
-----END RSA PRIVATE KEY-----
		`))
	ExpectNoErr(err, t)
	privateKey := key.(*rsa.PrivateKey)
	cert, err := DecodeCertificatePEM([]byte(`
-----BEGIN CERTIFICATE-----
MIIB4TCCAYugAwIBAgIUNXehXpBXahTamrUu5HNAv85FJyAwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzAzMTAyMTQxMjhaFw0yNDAz
MDkyMTQxMjhaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwXDANBgkqhkiG9w0BAQEF
AANLADBIAkEA33u0pEQbZ5QR/8O+IeqLVZ5VjAOuP0ymHrIaE5zJt+MMLm+Kiu4s
QTeLMAr9ZXQeWWAvT9JjqXACjcluJNEaHQIDAQABo1MwUTAdBgNVHQ4EFgQUjApm
pYWiYWEHj45zDS4fvw+3c2EwHwYDVR0jBBgwFoAUjApmpYWiYWEHj45zDS4fvw+3
c2EwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAANBAHgaTvPXpWIn4L1R
IMrJuXYdUSmXklMqMYlq3in7JG1wyEpyXycZcIxdkidNpvTVxx3nyaqwiGMSih66
6VQu1y8=
-----END CERTIFICATE-----	
	`), time.Now())
	ExpectNoErr(err, t)

	msg := "hello, world"

	_, sig, _ := Sign([]byte(msg), privateKey, cert)

	hashed := HashBytes([]byte(msg), SHA256)
	err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, hashed[:], sig)
	ExpectNoErr(err, t, "Error from verification: ")

	valid := (err == nil)
	if !valid {
		t.Fatalf("Verification failed.")
	}
}

func TestVerifyRSARaw(t *testing.T) {
	key, err := DecodePrivateKey([]byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIBPAIBAAJBAN97tKREG2eUEf/DviHqi1WeVYwDrj9Mph6yGhOcybfjDC5vioru
LEE3izAK/WV0HllgL0/SY6lwAo3JbiTRGh0CAwEAAQJBAJnR13/IsOQV8l2MKO3H
Naf0lwUL8372DtDJ3VDqdZzui+KfrTjA6ro0V1AGbs7Yd1YrJJk9G97/wCvtLO5r
x4ECIQD7coUOPPOdIm2NgSbrkDuvgDi35Pa5LKFTiHoXDZHxmQIhAOOHkdyIMeJw
LXssMN+/P/rmIAcLgP3YYrjaJcUIzgclAiEA2Q8M6TOYoSbdJ3A8JtGFlIS9cZHH
oiZyxWdk7Y2bVNECIDg/Bk7XGEXa51NgrEBTnfRfOSGktWGLQXRi8R1RPOVFAiEA
hq3voIKDTqDt1s8fd+p5DntwxoEaJN3OuLphnFNzkmY=
-----END RSA PRIVATE KEY-----
		`))
	ExpectNoErr(err, t)
	privateKey := key.(*rsa.PrivateKey)

	msg := "hello, world"

	hashed := HashBytes([]byte(msg), SHA256)
	sig, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, hashed[:])
	ExpectNoErr(err, t, "Error from signing: ")

	template := &x509.Certificate{
		SerialNumber:       big.NewInt(1234),
		SignatureAlgorithm: x509.SHA256WithRSA,
		NotAfter:           time.Now().Add(time.Second * +100),
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template,
		privateKey.Public(), privateKey)
	ExpectNoErr(err, t, "Certificate export failed: ")

	valid := VerifySignature([]byte(msg), sig, certificate, "RSA-SHA256", time.Now())
	if !valid {
		t.Fatalf("Signature validation failed.")
	}
}
