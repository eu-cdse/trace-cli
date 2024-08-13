// The CDAS Traceability Commandline Interface utility.
//
// This package implements the Commandline Interface (CLI) to interact with
// the CDAS Traceability service. The utility offers functionality for:
// creating traces, registering traces, and verifying downloaded products.
//
// Copyright 2023 Cloudflight Austria GmbH
package main

import (
	"bufio"
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

var version string // Injected by build

type Command string

const (
	CHECK    Command = "CHECK"
	HELP     Command = "HELP"
	PRINT    Command = "PRINT"
	PUBLISH  Command = "PUBLISH"
	REGISTER Command = "REGISTER"
	STATUS   Command = "STATUS"
	VERSION  Command = "VERSION"
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

func main() {
	log.SetFormatter(&log.TextFormatter{
		ForceColors:   true, // otherwise windows will use logfmt formatting since it has no TTY
		FullTimestamp: true,
		PadLevelText:  true,
	})
	log.SetLevel(log.WarnLevel)

	hash_func := flag.String("algorithm", string(BLAKE3), "The selected checksum algorithm, can be any of the following: SHA256, SHA3, BLAKE3.")
	cert_file := flag.String("cert", "", "The path to the PEM file holding the x509 certificate.")
	key_file := flag.String("ckey", "", "The path to the PEM file holding the private key for the certificate.")
	url := flag.String("url", "https://trace.dataspace.copernicus.eu/api", "The address to the traceabilty service API endpoint.")
	auth_token := flag.String("auth", "", "The bearer token for authentication against the API endpoint.")
	event := flag.String("event", "", "The trace event, can be any of the following: CREATE, COPY, DELETE.")
	obsolete := flag.String("obsolete", "", "Creates an OBSOLETE trace with the given reason for the products.")
	include_glob := flag.String("include", "", "A glob pattern defining the elements within an archive to include.")
	name := flag.String("name", "", "The product name for which the trace is generated. (default is the filename)")
	input_str := flag.String("input", "", "The input products based on which the product has been generated, as comma-separated pairs of NAME:HASH tuples, or [] to explicitly indicate no inputs.")
	verbose := flag.Bool("verbose", false, "Turn on verbose output.")
	debug := flag.Bool("debug", false, "Turn on debugging output.")
	insecure := flag.Bool("insecure", false, "Ignore insecure SSL certificates when connecting to the API endpoint.")
	stdin := flag.Bool("stdin", false, "Read from STDIN stream instead of FILE arguments")
	hash_value := flag.String("checksum", "", "The actual checksum for the trace to be generated in hexadecimal format. The checksum must be generated based on the provided algorithm and file. When specified the checksum will not be calculated - USE WITH CAUTION!")

	getopt.Alias("i", "include")
	getopt.Alias("v", "verbose")
	getopt.Alias("d", "debug")
	getopt.Alias("e", "event")
	opt_err := getopt.CommandLine.Parse(os.Args[1:]) // getopt.Parse() should exit, but doesn't
	if opt_err != nil {
		os.Exit(1)
	}

	if *verbose {
		log.SetLevel(log.InfoLevel)
	}
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	log.Infof("CDAS Trace CLI %s", version)

	hash_function := Algorithm(strings.ToUpper(*hash_func)).Validate()
	private_key := ValidateKeyFile(*key_file)
	certificate := ValidateCertFile(*cert_file)

	tmpl := TraceTemplate{
		Name:            name,
		Hash:            hash_value,
		Include_Pattern: ValidateIncludePattern(*include_glob),
		Inputs:          ValidateInputs(input_str),
	}

	if event != nil && len(*event) > 0 {
		tmpl.Event = TraceEvent(strings.ToUpper(*event)).Validate()

		switch tmpl.Event {
		case OBSOLETE:
			log.Fatalf("Use --obsolete option to specifiy OBSOLETE traces and not the --event option.")
		case COPY, DELETE:
			if *include_glob != "" || *input_str != "" {
				log.Warn("It is discouraged to supply contents or inputs for COPY or DELETE events.")
			}
		}
	}

	if (len(*key_file) != 0) != (len(*cert_file) != 0) {
		log.Error("If a certificate file is provide, also the private key file is required and v.v.")
		PrintUsageAndFail()
	}

	if obsolete != nil && len(*obsolete) > 0 {
		log.Infof("Marking products as OBSOLETE with reason '%s'", *obsolete)
		tmpl.Event = OBSOLETE
		tmpl.Obsolescence = obsolete
	} else {
		// Explicitly mark as nil to not send it to API
		tmpl.Obsolescence = nil
	}

	command_args := flag.Args()
	if len(command_args) < 1 {
		log.Error("No command provided.")
		PrintUsageAndFail()
	}
	command := Command(strings.ToUpper(command_args[0]))
	if command.RequiresArgs() && (len(command_args) < 2 && !*stdin) {
		log.Error("No files provided for which traces should be generated/checked.")
		PrintUsageAndFail()
	}
	if len(command_args) > 1 && *stdin {
		log.Error("Data can either be read from STDIN or from FILE..., but not both.")
		PrintUsageAndFail()
	}
	if *hash_value != "" {
		hash, err := DecodeHash(*hash_value)
		if err != nil {
			log.Errorf("The provided checksum '%s' could not be parsed: %v", *hash_value, err)
			PrintUsageAndFail()
		}
		// re-encode to ensure a unified format
		*hash_value = EncodeHash(hash)
		if tmpl.Event != DELETE && command != CHECK {
			// There are several elements that cannot be filled, e.g. product size.
			// If this is a DELETE trace, then it will not be kept in long term storage,
			// hence it is considered ok. But for all other cases it's better to be avoided.
			log.Warn("Supplying a checksum should generally be avoided for cases other than DELETE" +
				" as not all trace information is populated when skipping the hash calculation.")
		}
	}

	files := command_args[1:]

	var gerr error
	switch command {
	case CHECK:
		var check bool
		var err error
		if *hash_value != "" {
			hash, _ := DecodeHash(*hash_value)
			api := CreateClient(*url, auth_token, *insecure)
			check, err = CheckHash(hash, *name, api, hash_function)
		} else {
			readers, names, err_ := OpenFilesOrStdin(files, *stdin)
			if err_ != nil {
				gerr = err_
				break
			}
			api := CreateClient(*url, auth_token, *insecure)
			check, err = CheckProducts(readers, names, api, hash_function)
		}
		if err != nil {
			log.Errorf("%v", err)
		}
		if !check {
			gerr = fmt.Errorf("not all products could be validated successfully, e.g. because they're obsolete, signature check failed, or no trace was found")
		}
	case HELP:
		PrintUsageAndExit(true, 0)
	case PRINT:
		if *stdin {
			gerr = fmt.Errorf("STDIN processing not supported for print")
			break
		}
		tmpl.Event.Validate() // force this to be a valid event here
		traces := CreateProductTraces(files, &tmpl, hash_function, private_key, certificate)
		fmt.Printf("%s\n", FormatTraces(&traces))
	case PUBLISH:
		var readers []io.Reader
		readers, _, gerr = OpenFilesOrStdin(files, *stdin)
		if gerr != nil {
			break
		}
		api := CreateClient(*url, auth_token, *insecure)

		var traces []RegisterTrace
		for {
			if traces, gerr = ReadProductTraces(readers...); gerr != nil {
				break
			}
			log.Infof("Loaded %d traces.", len(traces))
			UpdateTraces(&traces, &tmpl, private_key, certificate)
			gerr = RegisterTraces(traces, api)
			if gerr != nil {
				log.Warn("Traces could not be registered, dumping for recovery.")
				fmt.Printf("%s\n", FormatTraces(&traces))

				// two options here, either continue and dump the remaining traces, or break with warning
				log.Warn("Additional traces from input might not have been loaded yet.")
				break
			}
		}
		if gerr == io.EOF {
			gerr = nil
		}
	case REGISTER:
		if *stdin {
			gerr = fmt.Errorf("STDIN processing not supported for register")
			break
		}
		tmpl.Event.Validate() // force this to be a valid event here
		traces := CreateProductTraces(files, &tmpl, hash_function, private_key, certificate)
		api := CreateClient(*url, auth_token, *insecure)
		gerr = RegisterTraces(traces, api)
		if gerr != nil {
			log.Warn("Traces could not be registered, dumping for recovery.")
			fmt.Printf("%s\n", FormatTraces(&traces))
		}
	case STATUS:
		gerr = CheckStatus(*url, *insecure)
	case VERSION:
		fmt.Printf("CDAS Trace CLI Version: %s\n", version)
	default:
		log.Errorf("Unknown command '%s'.\n", command_args[0])
		PrintUsageAndFail()
	}

	if gerr != nil {
		log.Errorf("Error: %v", gerr)
		os.Exit(1)
	}
}

func CheckStatus(url string, insecure bool) error {
	log.Infof("Checking API endpoint at %s", url)

	api := CreateClient(url, nil, insecure)

	res, err := api.PingStatusGetWithResponse(context.Background())
	if err != nil {
		return fmt.Errorf("unable to call API endpoint: %v", err)
	}

	if res.JSON200 != nil {
		log.Println("Service response:", *res.JSON200)
		return nil
	}

	return fmt.Errorf("invalid response from service: %v", res.Status())
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
	case CREATE, COPY, DELETE, OBSOLETE:
	case TraceEvent(""):
		log.Fatalf("Trace event undefined, please specify event using --event flag.")
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

func ValidateIncludePattern(pattern string) *glob.Glob {
	if pattern == "" {
		return nil
	}
	glob := glob.MustCompile(pattern)
	return &glob
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
	if input_string == nil || len(*input_string) == 0 {
		return nil
	} else if *input_string == "[]" {
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

func OpenFilesOrStdin(files []string, stdin bool) ([]io.Reader, []string, error) {
	if stdin {
		return []io.Reader{bufio.NewReader(os.Stdin)}, []string{"STDIN"}, nil
	}
	return OpenFiles(files)
}

func OpenFiles(files []string) ([]io.Reader, []string, error) {
	readers := make([]io.Reader, 0, len(files))
	names := make([]string, 0, len(files))
	for _, file := range files {
		r, err := os.Open(file)
		if err != nil {
			return readers, names, err
		}
		readers = append(readers, bufio.NewReader(r))
		names = append(names, file)
	}
	return readers, names, nil
}
