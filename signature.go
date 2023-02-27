// The CDAS Traceability Commandline Interface utility.
//
// This package implements the various crypotgraphic signature algorithms.
//
// Copyright 2023 Cloudflight Austria GmbH
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/youmark/pkcs8"

	log "github.com/sirupsen/logrus"
)

func Sign(data []byte, key any) (string, []byte, []byte) {
	log.Debugf("Signature Content\n---\n%s\n---\n", data)
	log.Debugf("Signature Content Bytes\n---\n%s\n---\n", EncodeHash(data))
	digest := HashBytes(data, SHA256)
	log.Debugf("Content Digest (SHA256): %s", EncodeHash(digest))

	var algorithm string
	var signature []byte
	var public []byte
	var sign_err error
	var key_err error

	switch key := key.(type) {
	case *rsa.PrivateKey:
		algorithm = "RSA-SHA256"
		signature, sign_err = key.Sign(rand.Reader, digest, crypto.SHA256)
		public, key_err = x509.MarshalPKIXPublicKey(key.Public())
	case *ecdsa.PrivateKey:
		algorithm = "ECDSA-SHA256"
		signature, sign_err = key.Sign(rand.Reader, digest, crypto.SHA256)
		public, key_err = x509.MarshalPKIXPublicKey(key.Public())
	case ed25519.PrivateKey:
		algorithm = "ED25519-SHA512" // ED25519 requires SHA512 and does it itself
		signature, sign_err = key.Sign(rand.Reader, data, crypto.Hash(0))
		public, key_err = x509.MarshalPKIXPublicKey(key.Public())
	default:
		log.Fatal("unknown type of private key")
	}
	log.Debugf("Signature Algoritm: %s", algorithm)

	if sign_err != nil {
		log.Fatalf("Unable to sign trace: " + sign_err.Error())
	}
	if key_err != nil {
		log.Fatalf("Unable to export public key: " + key_err.Error())
	}

	return algorithm, signature, public
}

func VerifySignature(data []byte, signature []byte, public_key []byte, algorithm string) bool {
	log.Debugf("Signature Algorithm: %s", algorithm)
	log.Debugf("Signature Content\n---\n%s\n---\n", data)
	log.Debugf("Signature Content Bytes: %s", EncodeHash(data))
	log.Debugf("Signature Bytes: %s", EncodeHash(signature))
	log.Debugf("Public Key Bytes: %s", EncodeHash(public_key))

	key, key_err := DecodePublicKey(public_key)
	if key_err != nil {
		log.Errorf("Unable to parse key")
		return false
	}

	sig_alg := strings.SplitN(algorithm, "-", 2)
	if len(sig_alg) != 2 {
		log.Errorf("Invalid signature algorithm: %s", algorithm)
		return false
	}

	var hash crypto.Hash
	hash_alg := Algorithm(sig_alg[1])
	switch hash_alg {
	case SHA256:
		hash = crypto.SHA256
	case Algorithm("SHA512"):
		hash = crypto.SHA512
	default:
		log.Errorf("Invalid hash used for signature: %s", hash_alg)
		return false
	}

	digest := HashBytes(data, hash_alg)

	var key_type string
	var verify bool

	switch key := key.(type) {
	case *rsa.PublicKey:
		key_type = "RSA"
		err := rsa.VerifyPKCS1v15(key, hash, digest, signature)
		verify = err == nil
		if err != nil {
			log.Warnf("Unable to verify signature: %v", err)
		}
	case *ecdsa.PublicKey:
		key_type = "ECDSA"
		verify = ecdsa.VerifyASN1(key, digest, signature)
	case ed25519.PublicKey:
		key_type = "ED25519"
		verify = ed25519.Verify(key, data, signature)
	default:
		log.Errorf("Invalid type of signture key: %s", sig_alg[0])
		return false
	}
	log.Debugf("Signature Key Algorithm: %s", key_type)

	if key_type != sig_alg[0] {
		log.Errorf("Invalid signature public key type %s, expected %s", key_type, sig_alg[0])
		return false
	}

	return verify
}

func DecodePrivateKey(data []byte, password ...string) any {
	block, _ := pem.Decode(data)
	if block == nil {
		log.Fatalf("Failed to decode PEM block of the private key.")
	}
	if x509.IsEncryptedPEMBlock(block) {
		log.Fatal("PEM Encryption is not supported, please use PKCS8 instead.")
	}

	key_bytes := block.Bytes

	switch block.Type {
	case "ENCRYPTED PRIVATE KEY":
		var pass = []byte{}
		if len(password) > 0 {
			pass = []byte(password[0])
		}
		if len(pass) == 0 {
			log.Fatalf("Encrypted private keys must have a non-empty password.")
		}

		key, err := pkcs8.ParsePKCS8PrivateKey(key_bytes, pass)
		if err != nil {
			log.Fatal("Failed to parse encrypted PK8 key: " + err.Error())
		}
		return key
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(key_bytes)
		if err != nil {
			log.Fatal("Failed to parse PK8 key: " + err.Error())
		}
		return key
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(key_bytes)
		if err != nil {
			log.Fatal("Failed to parse EC key: " + err.Error())
		}
		return key
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(key_bytes)
		if err != nil {
			log.Fatal("Failed to parse RSA key: " + err.Error())
		}
		return key
	default:
		log.Fatalf("Invalid private key supplied: %s", block.Type)
	}
	return nil
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
