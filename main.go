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
		traces := CreateProductInfos(files, include_pattern, trace_event)
		traces_json, _ := json.MarshalIndent(traces, "", "\t")
		fmt.Printf("%s\n", traces_json)
	case REGISTER:
		traces := CreateProductInfos(files, include_pattern, trace_event)
		RegisterTraces(traces, *url)
	case STATUS:
		CheckStatus(*url)
	default:
		log.Errorf("Unknown command '%s'.\n", command_args[0])
		PrintUsage()
		return
	}
}

func CreateProductInfos(files []string, include_pattern glob.Glob, event TraceEvent) []Trace {
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
		}
	}
	return traces
}
func CreateProductInfo(filename string, include_pattern glob.Glob) Product {
	hash, size := HashFile(filename)
	var p = Product{
		// Contents *map[string]string
		// Inputs *map[string]string
		Name: filename,
		Hash: EncodeHash(hash),
		Size: int(size),
	}

	if strings.HasSuffix(filename, ".zip") {
		p.Contents = HashContents(filename, include_pattern)
	}
	return p
}

func CheckProducts(files []string, url string) {
	log.WithFields(log.Fields{"files": files}).Infof("Checking traces for %d product(s)...", len(files))
	api := CreateClient(url)

	for _, filename := range files {
		CheckProduct(filename, api)
	}
}

func CheckProduct(filename string, api *ClientWithResponses) {
	hash, _ := HashFile(filename)
	res, err := api.SearchHashV1TracesHashHashGetWithResponse(context.Background(),
		EncodeHash(hash),
		&SearchHashV1TracesHashHashGetParams{
			Filehash: EncodeHash(hash),
		})
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
		for _, t := range *traces {
			// TODO signature check
			var check string
			if Algorithm(t.HashAlgorithm) == hash_function {
				check = "OK"
			} else {
				check = "FAIL"
			}
			fmt.Printf("\t%s\t%s\t%s\t%s\t%s\n", t.Timestamp.Format(time.RFC3339), t.Event, t.Origin, check, t.Product.Name)
		}
	}
}

func RegisterTraces(traces []Trace, url string) {
	api := CreateClient(url)

	res, err := api.PutTracesV1TracesPutWithResponse(context.Background(), traces)
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
