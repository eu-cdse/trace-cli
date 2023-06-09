// The CDAS Traceability Commandline Interface utility.
//
// This package implements the various crypotgraphic checksum algorithms.
//
// Copyright 2023 Cloudflight Austria GmbH
package main

import (
	"archive/zip"
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/sha3"
	// "crypto/sha256"
	"github.com/minio/sha256-simd"
	"github.com/zeebo/blake3"

	"github.com/gobwas/glob"
	log "github.com/sirupsen/logrus"
)

type Algorithm string

const (
	SHA256 Algorithm = "SHA256"
	SHA3   Algorithm = "SHA3"
	BLAKE3 Algorithm = "BLAKE3"
)

func EncodeHash(checksum []byte) string {
	return hex.EncodeToString(checksum)
}

func DecodeHash(checksum string) ([]byte, error) {
	return hex.DecodeString(checksum)
}

func HashContents(filename string, include_pattern glob.Glob, algorithm Algorithm) *map[string]string {
	r, err := zip.OpenReader(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	var contents = make(map[string]string)
	for _, f := range r.File {
		if strings.HasSuffix(f.Name, "/") {
			// log.Debugf("Skipping directory entry: '%s'", f.Name)
			continue
		}
		if !include_pattern.Match(f.Name) {
			log.Debugf("Skipping element, does not match include pattern: %s", f.Name)
			continue
		}

		rc, err := f.Open()
		if err != nil {
			log.Fatal(err)
		}
		sum := HashData(rc, algorithm)
		log.Debugf("%x %s\n", sum, f.Name)
		contents[f.Name] = EncodeHash(sum)
		rc.Close()
	}
	return &contents
}

func HashFile(filename string, algorithm Algorithm) ([]byte, int64) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	sum, size := HashStream(file, algorithm)
	log.Debugf("%x %s\n", sum, filename)

	return sum, size
}

type ByteCounter struct {
	Count int64
}

func (bc *ByteCounter) Write(p []byte) (n int, err error) {
	count := len(p)
	bc.Count += int64(count)
	return count, nil
}

func HashStream(reader io.Reader, algorithm Algorithm) ([]byte, int64) {
	bc := ByteCounter{}
	sum := HashData(io.TeeReader(reader, &bc), algorithm)
	return sum, bc.Count
}

func HashString(data string, algorithm Algorithm) []byte {
	return HashData(strings.NewReader(data), algorithm)
}
func HashBytes(data []byte, algorithm Algorithm) []byte {
	return HashData(bytes.NewReader(data), algorithm)
}

func HashData(src io.Reader, algorithm Algorithm) []byte {
	switch algorithm {
	case SHA3:
		hasher := sha3.New256()
		io.Copy(hasher, src)
		return hasher.Sum(nil)

	case SHA256:
		hasher := sha256.New()
		io.Copy(hasher, src)
		return hasher.Sum(nil)

	case BLAKE3:
		hasher := blake3.New()
		io.Copy(hasher, src)
		return hasher.Sum(nil)
	}
	return []byte{}
}
