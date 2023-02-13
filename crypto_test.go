package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/gobwas/glob"
)

func TestHashDataBlake3(t *testing.T) {
	data := "abcd1234"
	expected := "e8b21af482045332254fc63468995bac6a013a19c080a542c31289312d382b87"

	hash_function = BLAKE3
	bytes := HashData(strings.NewReader(data))
	actual := EncodeHash(bytes)

	if actual != expected {
		t.Fatalf("Results don't match. Expected '%v', Actual %v", expected, actual)
	}
}

func TestHashDataSha3(t *testing.T) {
	data := "abcd1234"
	expected := "6366c340328616f0393c1647ffd72b7252ce8ff0090240c095253f255c8edeb1"

	hash_function = SHA3
	bytes := HashData(strings.NewReader(data))
	actual := EncodeHash(bytes)

	if actual != expected {
		t.Fatalf("Results don't match. Expected '%v', Actual %v", expected, actual)
	}
}

func TestHashDataSha256(t *testing.T) {
	data := "abcd1234"
	expected := "e9cee71ab932fde863338d08be4de9dfe39ea049bdafb342ce659ec5450b69ae"

	hash_function = SHA256
	bytes := HashData(strings.NewReader(data))
	actual := EncodeHash(bytes)

	if actual != expected {
		t.Fatalf("Results don't match. Expected '%v', Actual %v", expected, actual)
	}
}

func TestHashFile(t *testing.T) {
	file := "test-data/test1.bin"
	expected_hash := "400a322239c83fbed043a8c9d898f2dd3d3634eeec0fab6fb0f577c1a56ada3a"
	expected_size := int64(10240)

	hash_function = BLAKE3
	bytes, actual_size := HashFile(file)
	actual_hash := EncodeHash(bytes)

	if actual_hash != expected_hash {
		t.Fatalf("Results don't match. Expected '%v', Actual %v", expected_hash, actual_hash)
	}
	if actual_size != expected_size {
		t.Fatalf("Results don't match. Expected '%v', Actual %v", expected_size, actual_size)
	}
}

func TestHashContents(t *testing.T) {
	file := "test-data/test.zip"
	expected := map[string]string{
		"test1.bin":         "400a322239c83fbed043a8c9d898f2dd3d3634eeec0fab6fb0f577c1a56ada3a",
		"test2.bin":         "41d066840196797b48b2b30ac31cd7a2d916ea690f6a364bd94fdd1823418f3e",
		"testdir/test3.bin": "a12959c6398697a95c097eebef1656ef686c92b1db60d537a942b6ce735f0285",
	}

	hash_function = BLAKE3
	actual := *HashContents(file, glob.MustCompile("*"))

	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("Results don't match. Expected '%v', Actual %v", expected, actual)
	}

	actual_file_pattern := *HashContents(file, glob.MustCompile("*.bin"))

	if !reflect.DeepEqual(actual_file_pattern, expected) {
		t.Fatalf("Results don't match. Expected '%v', Actual %v", expected, actual_file_pattern)
	}
}

func TestHashContentsPatternDir(t *testing.T) {
	file := "test-data/test.zip"
	expected := map[string]string{
		"testdir/test3.bin": "a12959c6398697a95c097eebef1656ef686c92b1db60d537a942b6ce735f0285",
	}

	hash_function = BLAKE3
	actual := *HashContents(file, glob.MustCompile("testdir/*.bin"))

	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("Results don't match. Expected '%v', Actual %v", expected, actual)
	}
}
