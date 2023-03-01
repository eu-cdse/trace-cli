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
		check := CheckProducts(files, *url)
		if !check {
			log.Error("Not all products could be validated successfully.")
			os.Exit(1)
		}
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
