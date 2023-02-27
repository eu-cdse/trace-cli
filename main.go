// The CDAS Traceability Commandline Interface utility.
//
// This package implements the Commandline Interface (CLI) to interact with
// the CDAS Traceability service. The utility offers functionality for:
// creating traces, registering traces, and verifying downloaded products.
//
// Copyright 2023 Cloudflight Austria GmbH
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gobwas/glob"
	"github.com/rsc/getopt"
	log "github.com/sirupsen/logrus"
)

type Command string

const (
	CHECK    Command = "CHECK"
	PRINT            = "PRINT"
	REGISTER         = "REGISTER"
	STATUS           = "STATUS"
)

func PrintUsage() {
	fmt.Printf(`
Usage:
  %s [OPTION...] COMMAND FILE...

Available Commands:
  check    Check the integrity and history of a given product
  print    Creates a new trace for a given product and prints it
  register Creates a new trace for a given product and registers it

Available Options:
`, os.Args[0])
	getopt.PrintDefaults()
}

// FIXME remove global, make argument
var hash_function Algorithm = BLAKE3

func main() {
	log.SetLevel(log.WarnLevel)

	hash_func := flag.String("algorithm", string(hash_function), "The selected checksum algorithm, can be any of the following: SHA256, SHA3, BLAKE3.")
	cert_file := flag.String("cert", "", "The path to the PEM file holding the private key.")
	url := flag.String("url", "https://64.225.133.55.nip.io/", "The address to the traceabilty service API endpoint.")
	event := flag.String("event", "CREATE", "The trace event, can be any of the following: CREATE, COPY, DELETE.")
	include_glob := flag.String("include", "*", "A glob pattern defining the elements within an archive to include.")
	verbose := flag.Bool("verbose", true, "Turn on verbose output.")
	debug := flag.Bool("debug", false, "Turn on debugging output.")

	getopt.Alias("i", "include")
	getopt.Alias("v", "verbose")
	getopt.Alias("d", "debug")
	getopt.Parse()

	if *verbose {
		log.SetLevel(log.InfoLevel)
	}
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	log.Info("CDAS Trace CLI")

	trace_event := TraceEvent(strings.ToUpper(*event)).Validate()
	hash_function = Algorithm(strings.ToUpper(*hash_func)).Validate()
	include_pattern := ValidateIncludePattern(*include_glob)
	private_key := ValidateCertFile(*cert_file)

	command_args := flag.Args()
	if len(command_args) < 1 {
		log.Error("No command provided.")
		PrintUsage()
		return
	}
	if len(command_args) < 2 {
		log.Error("No files provided for which traces should be generated/checked.")
		PrintUsage()
		return
	}

	files := command_args[1:]

	switch Command(strings.ToUpper(command_args[0])) {
	case CHECK:
		CheckProducts(files, *url)
	case PRINT:
		traces := CreateProductInfos(files, include_pattern, trace_event, private_key)
		traces_json, _ := json.MarshalIndent(traces, "", "\t")
		fmt.Printf("%s\n", traces_json)
	case REGISTER:
		traces := CreateProductInfos(files, include_pattern, trace_event, private_key)
		RegisterTraces(traces, *url)
	case STATUS:
		CheckStatus(*url)
	default:
		log.Errorf("Unknown command '%s'.\n", command_args[0])
		PrintUsage()
		return
	}
}

func CreateProductInfos(files []string, include_pattern glob.Glob, event TraceEvent, key any) []Trace {
	log.WithFields(log.Fields{"files": files}).Infof("Creating traces for %d product(s)...", len(files))
	traces := make([]Trace, len(files))
	for i, filename := range files {
		p := CreateProductInfo(filename, include_pattern)
		host, _ := os.Hostname()
		traces[i] = Trace{
			Event:         event,
			HashAlgorithm: string(hash_function),
			Product:       p,
			Timestamp:     time.Now(),
			Origin:        host,
			Signature:     CreateSignature(&p, key),
		}
	}
	return traces
}
func CreateProductInfo(filename string, include_pattern glob.Glob) Product {
	hash, size := HashFile(filename)
	var p = Product{
		Contents: &[]Content{}, //FIXME: necessary to align signature rn, should be nil
		Inputs:   &[]Input{},   //FIXME: necessary to align signature rn, should be nil
		Name:     filepath.Base(filename),
		Hash:     EncodeHash(hash),
		Size:     int(size),
	}

	if strings.HasSuffix(filename, ".zip") {
		contents := HashContents(filename, include_pattern)
		content_list := make([]Content, len(*contents))
		var i = 0
		for path, hash := range *contents {
			content_list[i].Path = path
			content_list[i].Hash = hash
			i += 1
		}
		p.Contents = &content_list
	}
	return p
}

func CreateSignature(p *Product, key any) Signature {
	if key == nil {
		return Signature{}
	}
	data := CreateSignatureContents(p)
	algorithm, signature, public_key := Sign(data, key)

	return Signature{
		Algorithm: algorithm,
		PublicKey: EncodeHash(public_key),
		Signature: EncodeHash(signature),
	}
}

func CreateSignatureContents(p *Product) []byte {
	data, _ := json.Marshal(p)
	return data
}

func CheckProducts(files []string, url string) bool {
	log.WithFields(log.Fields{"files": files}).Infof("Checking traces for %d product(s)...", len(files))
	api := CreateClient(url)

	var success = true

	for _, filename := range files {
		check := CheckProduct(filename, api)
		success = success && check // all products need to have a valid trace
	}

	return success
}

func CheckProduct(filename string, api *ClientWithResponses) bool {
	hash, _ := HashFile(filename)
	res, err := api.SearchHashV1WithResponse(context.Background(), EncodeHash(hash))
	if err != nil {
		log.Fatalf("Unable to call to API endpoint: %s", err)
	}

	if res.JSON200 == nil {
		log.Fatalf("Invalid response from service: %s\n%s", res.Status(), string(res.Body))
	}
	traces := res.JSON200
	// traces := &[]Trace{
	// 	CreateProductInfos([]string{filename}, glob.MustCompile("x"), CREATE)[0],
	// 	CreateProductInfos([]string{filename}, glob.MustCompile("x"), COPY)[0],
	// 	CreateProductInfos([]string{filename}, glob.MustCompile("x"), COPY)[0],
	// 	CreateProductInfos([]string{filename}, glob.MustCompile("x"), DELETE)[0],
	// }

	if traces == nil || len(*traces) == 0 {
		fmt.Printf("%s %s\tno traces found for checksum!\n", EncodeHash(hash), filename)
		//TODO also try other hash algorithms
	} else {
		fmt.Printf("%s %s\tfound %d traces:\n", EncodeHash(hash), filename, len(*traces))
		var success = false
		for _, t := range *traces {
			check, status := ValidateTrace(&t, hash, hash_function)

			fmt.Printf("\t%s  %10s %20s  %-25s %s\n",
				t.Timestamp.UTC().Format(time.RFC3339),
				t.Event,
				t.Origin,
				status,
				t.Product.Name)

			success = check || success // any trace match is considered success
		}
		return success
	}
	return false
}

func ValidateTrace(t *Trace, hash []byte, hash_func Algorithm) (bool, string) {
	log.WithFields(log.Fields{"trace": t}).Debug("Checking Trace")
	sig, sig_err := DecodeHash(t.Signature.Signature)
	key, key_err := DecodeHash(t.Signature.PublicKey)
	hash_str := EncodeHash(hash)

	if hash_func != Algorithm(t.HashAlgorithm) {
		return false, "FAIL (Wrong Algorithm)"
	} else if len(t.Product.Hash) == 0 || !(hash_str == t.Product.Hash ||
		ContentChecksumMatch(t.Product.Contents, hash_str)) {
		return false, "FAIL (Checksum Mismatch)"
		// } else if size != int64(t.Product.Size) { //Filename check only works on main product
		// 	check = "FAIL (Filesize Mismatch)"
	} else if len(t.Signature.Signature) == 0 {
		return true, "OK (Unsigned)"
	} else if sig_err != nil || key_err != nil ||
		VerifySignature(CreateSignatureContents(&t.Product), sig, key,
			t.Signature.Algorithm) == false {
		return false, "FAIL (Signature Invalid)"
	}
	return true, "OK"
}

func ContentChecksumMatch(contents *[]Content, checksum string) bool {
	if contents == nil {
		return false
			}
	for _, c := range *contents {
		if c.Hash == checksum {
			return true
		}
	}
	return false
}

func RegisterTraces(traces []Trace, url string) {
	api := CreateClient(url)

	res, err := api.PutTracesV1WithResponse(context.Background(), traces)
	if err != nil {
		log.Fatalf("Unable to call to API endpoint: %s", err)
	}

	registration := res.JSON201
	if registration != nil {
		if registration.Success {
			log.Infof("Registration successful: %s", registration.Message)
		} else {
			log.Errorf("Registration failed: %s", registration.Message)
		}
	} else {
		log.Errorf("Invalid response from service: %s", res.Status())
	}
}

func CheckStatus(url string) {
	log.Infof("Checking API endpoint at %s", url)

	api := CreateClient(url)

	res, err := api.PingStatusGetWithResponse(context.Background())
	if err != nil {
		log.Fatalf("Unable to call to API endpoint: %s", err)
	}

	if res.JSON200 != nil {
		log.Println("Service response:", *res.JSON200)
	} else {
		log.Errorf("Invalid response from service: %s", res.Status())
	}
}

func CreateClient(url string) *ClientWithResponses {
	skip_cert_verify := func(c *Client) error {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		c.Client = &http.Client{Transport: tr}
		return nil
	}

	api, err := NewClientWithResponses(url, skip_cert_verify)
	if err != nil {
		log.Fatalf("Unable to connect to API endpoint: %s", err)
	}
	return api
}

func (ev TraceEvent) Validate() TraceEvent {
	switch ev {
	case CREATE, COPY, DELETE:
	default:
		log.Fatalf("Unknown trace event '%s'", ev)
	}
	return ev
}

func (a Algorithm) Validate() Algorithm {
	switch a {
	case SHA3, SHA256, BLAKE3:
	default:
		log.Fatalf("Unknown hash function '%s'", a)
	}
	log.Info("Using hash algorithm ", a)
	return a
}
func ValidateIncludePattern(pattern string) glob.Glob {
	return glob.MustCompile(pattern)
}

func ValidateCertFile(certfile string) any {
	if len(certfile) == 0 {
		return nil
	}
	key_bytes, err := os.ReadFile(certfile)
	if err != nil {
		log.Fatalf("Unable to read PEM file holding the private key for signing from '%s': %s", certfile, err.Error())
	}

	key := DecodePrivateKey(key_bytes)
	return key
}
