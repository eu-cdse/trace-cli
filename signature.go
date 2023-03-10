// The CDAS Traceability Commandline Interface utility.
//
// This package implements the various crypotgraphic signature algorithms.
//
// Copyright 2023 Cloudflight Austria GmbH
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/youmark/pkcs8"

	log "github.com/sirupsen/logrus"
)

func Sign(data []byte, key any, cert any) (string, []byte, []byte) {
	certificate := cert.(*x509.Certificate)

	log.Debugf("Signature Content\n---\n%s\n---\n", data)
	log.Debugf("Signature Content Bytes\n---\n%s\n---\n", EncodeHash(data))

	// It would be better to read the signature algorithm from certificate and re-use that.
	digest := HashBytes(data, SHA256)
	log.Debugf("Content Digest (SHA256): %s", EncodeHash(digest))

	var algorithm string
	var signature []byte
	var sign_err error

	switch key := key.(type) {
	case *rsa.PrivateKey:
		algorithm = "RSA-SHA256"
		if certificate.SignatureAlgorithm != x509.SHA256WithRSA {
			log.Fatalf("Unspported signature algorithm in certificate: %v. Only %v supported for the given private key.",
				certificate.SignatureAlgorithm.String(), algorithm)
		}
		if !key.Public().(*rsa.PublicKey).Equal(certificate.PublicKey) {
			log.Fatalf("Certificate has not been generated with the given private key, public key does not match: %v vs %v.",
				key.Public(), certificate.PublicKey)
		}
		signature, sign_err = key.Sign(rand.Reader, digest, crypto.SHA256)
	case *ecdsa.PrivateKey:
		algorithm = "ECDSA-SHA256"
		if certificate.SignatureAlgorithm != x509.ECDSAWithSHA256 {
			log.Fatalf("Unspported signature algorithm in certificate: %v. Only %v supported for the given private key.",
				certificate.SignatureAlgorithm.String(), algorithm)
		}
		if !key.Public().(*ecdsa.PublicKey).Equal(certificate.PublicKey) {
			log.Fatalf("Certificate has not been generated with the given private key, public key does not match: %v vs %v.",
				key.Public(), certificate.PublicKey)
		}
		signature, sign_err = key.Sign(rand.Reader, digest, crypto.SHA256)
	default:
		log.Fatal("unknown type of private key")
	}
	log.Debugf("Signature Algoritm: %s, in Certificate: %s", algorithm, certificate.SignatureAlgorithm.String())

	if sign_err != nil {
		log.Fatalf("Unable to sign trace: " + sign_err.Error())
	}
	return algorithm, signature, certificate.Raw
}

func VerifySignature(message []byte, signature []byte, certificate []byte, algorithm string, sign_time time.Time) bool {
	log.Debugf("Signature Algorithm: %s", algorithm)
	log.Debugf("Signature Content\n---\n%s\n---\n", message)
	log.Debugf("Signature Content Bytes: %s", EncodeHash(message))
	log.Debugf("Signature Bytes: %s", EncodeHash(signature))
	log.Debugf("Certificate Bytes: %s", EncodeHash(certificate))

	cert, err := DecodeCertificateDER(certificate, sign_time)
	if err != nil {
		log.Errorf("Unable to decode signature certificate: %v", err)
		return false
	}
	log.Debugf("Signature Key Algorithm: %s", cert.SignatureAlgorithm.String())

	check_err := cert.CheckSignature(cert.SignatureAlgorithm, message, signature)
	if check_err != nil {
		log.Warnf("Signature validation failed: %v", check_err)
		return false
	}
	return true
}

func DecodePrivateKey(key_pem []byte, password ...func() string) (any, error) {
	block, _ := pem.Decode(key_pem)
	if block == nil {
		return nil, fmt.Errorf("Failed to decode PEM block of the private key.")
	}
	if x509.IsEncryptedPEMBlock(block) {
		return nil, fmt.Errorf("PEM Encryption is not supported, please use PKCS8 instead.")
	}

	key_bytes := block.Bytes

	var key any
	var err error

	switch block.Type {
	case "ENCRYPTED PRIVATE KEY":
		var pass = []byte{}
		if len(password) > 0 {
			pass = []byte(password[0]())
		}
		if len(pass) == 0 {
			// this is currently a bug in pkcs8 lib.
			// golang pkcs8 can't handle encrpytion at all.
			return nil, fmt.Errorf("Encrypted private keys must have a non-empty password.")
		}

		key, err = pkcs8.ParsePKCS8PrivateKey(key_bytes, pass)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse encrypted PK8 key: %v", err)
		}
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(key_bytes)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse PK8 key: %v", err)
		}
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(key_bytes)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse EC key: %v", err)
		}
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(key_bytes)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse RSA key: %v", err)
		}
	default:
		return nil, fmt.Errorf("Invalid private key supplied: %s", block.Type)
	}
	return key, err
}

func DecodePublicKey(public_key []byte) (any, error) {
	key, err := x509.ParsePKIXPublicKey(public_key)
	if err != nil {
		log.Debugf("Key bytes: \n%s", EncodeHash(public_key))
		log.Errorf("Unable to parse public key: %s", err.Error())
		return nil, err
	}
	return key, nil
}

func DecodeCertificatePEM(certificate_pem []byte, sign_time time.Time) (*x509.Certificate, error) {
	block, _ := pem.Decode(certificate_pem)
	if block == nil {
		return nil, fmt.Errorf("Failed to decode PEM block of the certificate.")
	}
	if x509.IsEncryptedPEMBlock(block) {
		return nil, fmt.Errorf("PEM encryption of the certificate is not supported.")
	}

	return DecodeCertificateDER(block.Bytes, sign_time)
}

func DecodeCertificateDER(certificate_der []byte, sign_time time.Time) (*x509.Certificate, error) {
	certificate, err := x509.ParseCertificate(certificate_der)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse certificate: %v", err)
	}

	if sign_time.Before(certificate.NotBefore) || sign_time.After(certificate.NotAfter) {
		log.Warnf("Certificate is expired: %v is not in valid range [%v, %v]",
			sign_time, certificate.NotBefore, certificate.NotAfter)
	}
	return certificate, nil
}
