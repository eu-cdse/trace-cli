package main

import (
	"strings"
	"testing"

	"crypto"
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
	_, err := DecodePrivateKey([]byte(pemfile), "abc123")
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
	bytes, _ := DecodeHash(key_hex)
	_, err := DecodePublicKey(bytes)
	ExpectNoErr(err, t, "Unable to parse key: ")
}

func TestDecodePublicKeyECDSA(t *testing.T) {
	key_hex := "3059301306072a8648ce3d020106082a8648ce3d03010703420004d2c89d7b404adc81516efd9cec0cb48d1c48f2583f6dcdd88e617309e883f3d69594bb72aabb211d0c1b348f7af7d3b6b89a29220ff33c637f61f8b1a6d6e3e6"
	bytes, err := DecodeHash(key_hex)
	ExpectNoErr(err, t, "Decoding Hash: ")
	_, err = DecodePublicKey(bytes)
	ExpectNoErr(err, t, "Unable to parse key: ")
}

func TestSignVerifyRSA(t *testing.T) {
	// text := strings.Repeat("abc123", 100)
	text := "hello, world"
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

	algorithm, signature, public_bytes := Sign([]byte(text), private_key)

	if algorithm != "RSA-SHA256" {
		t.Errorf("Signature algorithm unexpected: %s", algorithm)
	}

	valid := VerifySignature([]byte(text), signature, public_bytes, algorithm)

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

	algorithm, signature, public_bytes := Sign([]byte(text), private_key)

	if algorithm != "ECDSA-SHA256" {
		t.Errorf("Signature algorithm unexpected: %s", algorithm)
	}

	valid := VerifySignature([]byte(text), signature, public_bytes, algorithm)

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

	msg := "hello, world"

	_, sig, _ := Sign([]byte(msg), privateKey)

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

	public_bytes, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	ExpectNoErr(err, t, "Key export failed: ")

	valid := VerifySignature([]byte(msg), sig, public_bytes, "RSA-SHA256")
	if !valid {
		t.Fatalf("Signature validation failed.")
	}

}
