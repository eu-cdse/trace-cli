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
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gobwas/glob"
	"github.com/rsc/getopt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/term"
)

type Command string

const (
	CHECK    Command = "CHECK"
	HELP             = "HELP"
	PRINT            = "PRINT"
	PUBLISH          = "PUBLISH"
	REGISTER         = "REGISTER"
	STATUS           = "STATUS"
	VERSION          = "VERSION"
)

func (cmd Command) RequiresArgs() bool {
	switch cmd {
	case CHECK, PRINT, REGISTER, PUBLISH:
		return true
	}
	return false
}

func PrintUsageAndExit(examples bool, exitcode int) {
	binary := os.Args[0]
	fmt.Printf(`
Usage:
  %s [OPTION...] COMMAND FILE...

Available Commands:
  check    Check the integrity and history of a given FILE
  help     Print usage and examples
  print    Create a new trace for a given FILE and print it, but do not register it
  publish  Register an existing trace, e.g. created by print, and passed as FILE
  register Create a new trace for a given FILE and register it
  version  Display version and exit

Available Options:
`, binary)
	getopt.PrintDefaults()
	if examples {
		fmt.Printf(`
Examples:
  Check a product for its integrity and trace history:
    %s check s1a-iw-grd-vv-20230330t051016-20230330t051041-047869-05c07e-001.tiff 

  Register a trace for a newly created product including its bands as content:
    %s --auth TOKEN --cert certificate.crt --ckey private.pem --event create --include "bands/*.nc" register product.zip

  Print the trace for a copy of a product but do not register it:
    %s --cert certificate.crt --ckey private.pem --event copy print product.nc

  Mark a product as obsolete:
    %s --auth TOKEN --cert certificate.crt --ckey private.pem --obsolete "Product has been replaced by product2.zip" register product1.zip
  
`, binary, binary, binary, binary)
	}
	os.Exit(exitcode)
}
func PrintUsageAndFail() {
	PrintUsageAndExit(false, 1)
}

var hash_function Algorithm = BLAKE3 // FIXME remove global, make argument

var version string // Injected by build

func main() {
	log.SetLevel(log.WarnLevel)

	hash_func := flag.String("algorithm", string(hash_function), "The selected checksum algorithm, can be any of the following: SHA256, SHA3, BLAKE3.")
	cert_file := flag.String("cert", "", "The path to the PEM file holding the x509 certificate.")
	key_file := flag.String("ckey", "", "The path to the PEM file holding the private key for the certificate.")
	url := flag.String("url", "https://64.225.133.55.nip.io/", "The address to the traceabilty service API endpoint.")
	auth_token := flag.String("auth", "", "The bearer token for authentication against the API endpoint.")
	event := flag.String("event", "CREATE", "The trace event, can be any of the following: CREATE, COPY, DELETE.")
	obsolete := flag.String("obsolete", "", "Creates an OBSOLETE trace with the given reason for the products.")
	include_glob := flag.String("include", "*", "A glob pattern defining the elements within an archive to include.")
	name := flag.String("name", "", "The product name for which the trace is generated. (default is the filename)")
	input_str := flag.String("input", "", "The input products based on which the product has been generated, as comma-separated pairs of NAME:HASH tuples.")
	verbose := flag.Bool("verbose", false, "Turn on verbose output.")
	debug := flag.Bool("debug", false, "Turn on debugging output.")
	insecure := flag.Bool("insecure", true, "Ignore insecure SSL certificates when connecting to the API endpoint.")

	getopt.Alias("i", "include")
	getopt.Alias("v", "verbose")
	getopt.Alias("d", "debug")
	getopt.Alias("e", "event")
	getopt.Parse()

	if *verbose {
		log.SetLevel(log.InfoLevel)
	}
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	log.Infof("CDAS Trace CLI %s", version)

	trace_event := TraceEvent(strings.ToUpper(*event)).Validate()
	hash_function = Algorithm(strings.ToUpper(*hash_func)).Validate()
	include_pattern := ValidateIncludePattern(*include_glob)
	inputs := ValidateInputs(input_str)
	private_key := ValidateKeyFile(*key_file)
	certificate := ValidateCertFile(*cert_file)

	if (len(*key_file) != 0) != (len(*cert_file) != 0) {
		log.Error("If a certificate file is provide, also the private key file is required and v.v.")
		PrintUsageAndFail()
	}

	if obsolete != nil && len(*obsolete) > 0 {
		log.Infof("Marking products as OBSOLETE with reason '%s'", *obsolete)
		trace_event = OBSOLETE
	} else {
		// Explicitly mark as nil to not send it to API
		obsolete = nil
	}

	command_args := flag.Args()
	if len(command_args) < 1 {
		log.Error("No command provided.")
		PrintUsageAndFail()
	}
	command := Command(strings.ToUpper(command_args[0]))
	if command.RequiresArgs() && len(command_args) < 2 {
		log.Error("No files provided for which traces should be generated/checked.")
		PrintUsageAndFail()
	}

	files := command_args[1:]

	var err error
	switch command {
	case CHECK:
		var check bool
		api := CreateClient(*url, auth_token, *insecure)
		check, err = CheckProducts(files, api)
		if !check {
			log.Error("Not all products could be validated successfully.")
		}
	case HELP:
		PrintUsageAndExit(true, 0)
	case PRINT:
		traces := CreateProductTraces(files, name, include_pattern, inputs, trace_event, obsolete, private_key, certificate)
		fmt.Printf("%s\n", FormatTraces(&traces))
	case PUBLISH:
		// todo print warning if arguments were set that are not used?
		var readers []io.Reader
		readers, err = OpenFiles(files)
		if err != nil {
			break
		}
		var traces []RegisterTrace
		traces, err = ReadProductTraces(readers...)
		if err != nil {
			break
		}
		api := CreateClient(*url, auth_token, *insecure)
		err = RegisterTraces(traces, api)
		if err != nil {
			log.Warn("Traces could not be registered, dumping for recovery.")
			fmt.Printf("%s\n", FormatTraces(&traces))
		}
	case REGISTER:
		traces := CreateProductTraces(files, name, include_pattern, inputs, trace_event, obsolete, private_key, certificate)
		api := CreateClient(*url, auth_token, *insecure)
		err = RegisterTraces(traces, api)
		if err != nil {
			log.Warn("Traces could not be registered, dumping for recovery.")
			fmt.Printf("%s\n", FormatTraces(&traces))
		}
	case STATUS:
		err = CheckStatus(*url, *insecure)
	case VERSION:
		fmt.Printf("CDAS Trace CLI Version: %s\n", version)
	default:
		log.Errorf("Unknown command '%s'.\n", command_args[0])
		PrintUsageAndFail()
	}

	if err != nil {
		log.Errorf("%v", err)
		os.Exit(1)
	}
}

func CheckStatus(url string, insecure bool) error {
	log.Infof("Checking API endpoint at %s", url)

	api := CreateClient(url, nil, insecure)

	res, err := api.PingStatusGetWithResponse(context.Background())
	if err != nil {
		return fmt.Errorf("Unable to call API endpoint: %v", err)
	}

	if res.JSON200 != nil {
		log.Println("Service response:", *res.JSON200)
		return nil
	}

	return fmt.Errorf("Invalid response from service: %s", res.Status())
}

func CreateClient(url string, auth_token *string, insecure bool) *ClientWithResponses {
	skip_cert_verify := func(c *Client) error {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		c.Client = &http.Client{Transport: tr}
		return nil
	}

	auth_handler := func(ctx context.Context, req *http.Request) error {
		req.Header.Add("Authorization", "Bearer "+*auth_token)
		return nil
	}

	options := make([]ClientOption, 0, 2)
	if insecure {
		options = append(options, skip_cert_verify)
	}
	if auth_token != nil {
		options = append(options, WithRequestEditorFn(auth_handler))
	}

	api, err := NewClientWithResponses(url, options...)

	if err != nil {
		log.Fatalf("Unable to connect to API endpoint: %s", err)
	}
	return api
}

func (ev TraceEvent) Validate() TraceEvent {
	switch ev {
	case CREATE, COPY, DELETE:
	case OBSOLETE:
		log.Fatalf("Use --obsolete option to specifiy OBSOLETE traces.")
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

func ValidateKeyFile(keyfile string) any {
	if len(keyfile) == 0 {
		return nil
	}
	key_bytes, err := os.ReadFile(keyfile)
	if err != nil {
		log.Fatalf("Unable to read PEM file holding the private key for signing from '%s': %s", keyfile, err.Error())
	}

	stdin_pass := func() string {
		fmt.Print("Please enter password for private key: ")
		pass, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			log.Fatalf("Unable to read password: %v", err)
		}
		fmt.Println()
		return string(pass)
	}

	key, err := DecodePrivateKey(key_bytes, stdin_pass)
	if err != nil {
		log.Fatalf("%v", err)
	}
	return key
}

func ValidateCertFile(certfile string) any {
	if len(certfile) == 0 {
		return nil
	}
	cert_bytes, err := os.ReadFile(certfile)
	if err != nil {
		log.Fatalf("Unable to read PEM file holding the certificate for signing from '%s': %s", certfile, err.Error())
	}

	cert, err := DecodeCertificatePEM(cert_bytes, time.Now())
	if err != nil {
		log.Fatalf("Unable to decode certificate: %v", err)
	}
	return cert
}

func ValidateInputs(input_string *string) *[]Input {
	if input_string == nil {
		return nil
	} else if len(*input_string) == 0 {
		return &[]Input{}
	}
	tuples := strings.Split(*input_string, ",")
	inputs := make([]Input, len(tuples))
	for i, tuple := range tuples {
		parts := strings.Split(tuple, ":")
		if len(parts) != 2 {
			log.Fatalf("Invalid inputs string, expect a comma-separated list of NAME:HASH pairs, but got '%v'. Problem at: %v",
				*input_string, parts)
		}
		inputs[i].Name = parts[0]
		inputs[i].Hash = parts[1]
	}
	return &inputs
}

func OpenFiles(files []string) ([]io.Reader, error) {
	readers := make([]io.Reader, 0, len(files))
	for _, file := range files {
		r, err := os.Open(file)
		if err != nil {
			return readers, err
		}
		readers = append(readers, r)
	}
	return readers, nil
}
