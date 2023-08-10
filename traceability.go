// The CDAS Traceability Commandline Interface utility.
//
// This package implements the API endpoint handling.
//
// Copyright 2023 Cloudflight Austria GmbH
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/gobwas/glob"
	log "github.com/sirupsen/logrus"
)

func ReadProductTraces(readers ...io.Reader) ([]RegisterTrace, error) {
	traces := make([]RegisterTrace, 0, len(readers))
	var err error
	for _, reader := range readers {
		err = ReadProductTracesAppend(reader, &traces)
		if err != nil {
			return []RegisterTrace{}, err
		}
	}
	return traces, err
}

type SingleByteReader struct {
	rd io.Reader
}

func (rd *SingleByteReader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return rd.rd.Read(p)
	}
	return rd.rd.Read(p[:1])
}

func ReadProductTracesAppend(reader io.Reader, traces *[]RegisterTrace) error {
	// the decoder manages its own buffer and reads ahead
	// thus we need to limit it to reading only 1 byte at a time.
	byte_reader := &SingleByteReader{reader}

	var t []RegisterTrace
	decoder := json.NewDecoder(byte_reader)
	err := decoder.Decode(&t)
	if err != nil {
		return err
	}

	// we only append traces here, this does not check for duplicates
	*traces = append(*traces, t...)
	return nil
}

type TraceTemplate struct {
	Name            *string
	Hash            *string
	Include_Pattern glob.Glob
	Inputs          *[]Input
	Event           TraceEvent
	Obsolescence    *string
}

func CreateProductTraces(files []string, template *TraceTemplate, hasher Algorithm, key any, cert any) []RegisterTrace {
	log.WithFields(log.Fields{"files": files}).Infof("Creating traces for %d product(s)...", len(files))
	if template.Name != nil && *template.Name != "" && len(files) > 1 {
		log.Warn("Product name was specified, but traces for multiple products were requested; the specified product name will be ignored.")
		template.Name = nil
	}
	traces := make([]RegisterTrace, len(files))
	for i, filename := range files {
		p := CreateProductInfo(filename, template, hasher)
		traces[i] = RegisterTrace{
			Event:         template.Event,
			HashAlgorithm: string(hasher),
			Obsolescence:  template.Obsolescence,
			Product:       p,
		}
		sig := CreateSignature(&traces[i], key, cert)
		traces[i].Signature = sig
	}
	return traces
}

func CreateProductInfo(filename string, template *TraceTemplate, hasher Algorithm) Product {
	var p = Product{
		Inputs: template.Inputs,
	}

	if template.Hash != nil && len(*template.Hash) > 0 {
		log.Infof("Skipping hash, using supplied checksum: %s", *template.Hash)
		p.Hash = *template.Hash
		p.Size = 0 // This is not good, but the only option here => ensure that provision of hash is limited
	} else {
		hash, size := HashFile(filename, hasher)
		p.Hash = EncodeHash(hash)
		p.Size = size
	}

	if template.Name != nil && len(*template.Name) > 0 {
		p.Name = *template.Name
	} else {
		p.Name = filepath.Base(filename)
	}

	if strings.HasSuffix(filename, ".zip") {
		contents := HashContents(filename, template.Include_Pattern, hasher)
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

func CreateSignature(t *RegisterTrace, key any, cert any) Signature {
	if key == nil {
		return Signature{}
	}
	data := CreateSignatureContents(&t.Product, t.Event)
	algorithm, signature, certificate := Sign(data, key, cert)

	return Signature{
		Algorithm:   algorithm,
		Certificate: EncodeBytes(certificate),
		Signature:   EncodeBytes(signature),
		Message:     string(data),
	}
}

// wrapper to extend simple product
// just putting the product in signature is not enough, at least trace event should be cloned
// ideally we could use some common baseclass between RegisterTrace and Trace, but there is none.
type SignatureContents struct {
	Product
	Event TraceEvent `json:"event"`
}

func CreateSignatureContents(p *Product, event TraceEvent) []byte {
	contents := SignatureContents{*p, event}
	data, err := json.Marshal(contents)
	if err != nil {
		log.Warnf("Unable to marshall trace content for signature: %v", err)
	}
	return data
}

func UpdateTraces(traces *[]RegisterTrace, template *TraceTemplate, key any, cert any) {
	log.Infof("Updating %d trace(s)...", len(*traces))
	if template.Name != nil && *template.Name != "" && len(*traces) > 1 {
		log.Warn("Product name was specified, but traces for multiple products were requested; the specified product name will be ignored.")
		template.Name = nil
	}

	sig_reset := false

	for i, trace := range *traces {
		if template.Name != nil && *template.Name != "" && *template.Name != trace.Product.Name {
			log.Infof("Updating name in trace to '%s'", *template.Name)
			(*traces)[i].Product.Name = *template.Name
			sig_reset = true
		}
		if template.Hash != nil && *template.Hash != "" && *template.Hash != trace.Product.Hash {
			log.Infof("Updating hash in trace to '%s'", *template.Hash)
			(*traces)[i].Product.Hash = *template.Hash
			sig_reset = true
		}
		if template.Event != TraceEvent("") && template.Event != trace.Event {
			log.Infof("Updating event in trace to '%s'", template.Event)
			if trace.Event == OBSOLETE {
				// reset obsolescence message if new event is something else
				// (which it is, otherwise we wouldn't update it)
				(*traces)[i].Obsolescence = nil
			}
			(*traces)[i].Event = template.Event
			sig_reset = true
		}
		if template.Obsolescence != nil && (trace.Obsolescence == nil || *template.Obsolescence != *trace.Obsolescence) {
			log.Infof("Updating obsolescene in trace to '%s'", *template.Obsolescence)
			(*traces)[i].Obsolescence = template.Obsolescence
			sig_reset = true
		}

		if key != nil && cert != nil {
			log.Infof("Updating signature in trace using provided certificate")
			sig := CreateSignature(&(*traces)[i], key, cert)
			(*traces)[i].Signature = sig
		} else if sig_reset {
			log.Warnf("Resetting signature because trace elements changed and no certificate was provided.")
			(*traces)[i].Signature = Signature{}
		}
	}
}

func FormatTraces(traces *[]RegisterTrace) string {
	traces_json, _ := json.MarshalIndent(traces, "", "\t")
	return string(traces_json)
}

func CheckProducts(readers []io.Reader, names []string, api *ClientWithResponses, hasher Algorithm) (bool, error) {
	log.WithFields(log.Fields{"files": names}).Infof("Checking traces for %d product(s)...", len(names))

	var success = true

	for i := range readers {
		check, err := CheckProduct(readers[i], names[i], api, hasher)
		if err != nil {
			return false, err
		}
		success = success && check // all products need to have a valid trace
	}
	return success, nil
}

func CheckProduct(reader io.Reader, name string, api *ClientWithResponses, hasher Algorithm) (bool, error) {
	log.Debugf("Checking traces for %s", name)
	hash := HashData(reader, hasher)
	res, err := api.SearchHashV1WithResponse(context.Background(), EncodeHash(hash))
	if err != nil {
		return false, fmt.Errorf("unable to call API endpoint: %v", err)
	}

	if res.JSON200 == nil {
		if res.StatusCode() == 404 {
			log.Errorf("No traces found for %s %s: %s\n", name, EncodeHash(hash), string(res.Body))
			return false, nil
		}
		return false, fmt.Errorf("invalid response from service: %s\n%s", res.Status(), string(res.Body))
	}
	if traces := res.JSON200; traces == nil || len(*traces) == 0 {
		fmt.Printf("%s %s\tno traces found for checksum!\n", EncodeHash(hash), name)
		//TODO also try other hash algorithms
	} else {
		fmt.Printf("%s %s\tfound %d traces:\n", EncodeHash(hash), name, len(*traces))
		var success = false

		sort.Slice(*traces, func(i, j int) bool {
			return (*traces)[i].Timestamp.Before((*traces)[j].Timestamp)
		})

		for _, t := range *traces {
			check, status := ValidateTrace(&t, hash, hasher)
			obsolescence := ""
			if t.Obsolescence != nil {
				obsolescence = " => " + *t.Obsolescence
			}

			//TODO print signature information (e.g. issuer)
			fmt.Printf("\t%s  %10s %20s  %-25s %s %s\n",
				t.Timestamp.UTC().Format(time.RFC3339),
				t.Event,
				t.Origin,
				status,
				t.Product.Name,
				obsolescence)

			success = check || success // any trace match is considered success
		}
		return success, nil
	}
	return false, nil
}

func ValidateTrace(t *Trace, hash []byte, hash_func Algorithm) (bool, string) {
	log.WithFields(log.Fields{"trace": t}).Debug("Checking Trace")
	sig_bytes, sig_err := DecodeBytes(t.Signature.Signature)
	cer_bytes, key_err := DecodeBytes(t.Signature.Certificate)
	hash_str := EncodeHash(hash)

	if hash_func != Algorithm(t.HashAlgorithm) {
		return false, "FAIL (Wrong Algorithm)"
	} else if len(t.Product.Hash) == 0 || !(hash_str == t.Product.Hash ||
		ContentChecksumMatch(t.Product.Contents, hash_str)) {
		return false, "FAIL (Checksum Mismatch)"
	} else if len(t.Signature.Signature) == 0 {
		return true, "OK (Unsigned)"
	} else if sig_err != nil || key_err != nil {
		return false, "FAIL (Signature Decode)"
	} else if !VerifySignature([]byte(t.Signature.Message), sig_bytes, cer_bytes, t.Signature.Algorithm, t.Timestamp) {
		return false, "FAIL (Signature Invalid)"
	} else if !SignatureTraceMatch(t, t.Signature.Message) {
		return false, "FAIL (Signature Mismatch)"
	} else if !SignatureOriginMatch() {
		return false, "FAIL (Signature Origin)" // or OK (...)?
	} else if !SignatureTimestampMatch() {
		return false, "FAIL (Signature Expired)" // or OK (...)?
	} else if t.Event == OBSOLETE {
		return true, "OK (Obsolete)"
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

type json_map map[string]interface{}

func check_match(actual json_map, expected json_map, key string, required bool) bool {
	e, e_ok := expected[key]
	a, a_ok := actual[key]
	if required {
		// all must be present and match
		return e_ok && a_ok && reflect.DeepEqual(a, e)
	}
	// must only match if present
	return !a_ok || !e_ok || reflect.DeepEqual(a, e)
}

func SignatureTraceMatch(trace *Trace, message string) bool {
	// check if signature was created with same version
	current := CreateSignatureContents(&trace.Product, trace.Event)
	if string(current) == message {
		log.Debugf("Trace signature is exact match.")
		return true
	}

	// fallback fuzzy matching
	log.Debugf("Fuzzy matching trace signature: %v\ncurrent: %v", message, string(current))

	var expected json_map
	err := json.Unmarshal(current, &expected)
	if err != nil {
		log.Errorf("Failure decoding internal signature message: %v", err)
		return false
	}

	var actual json_map
	err = json.Unmarshal([]byte(message), &actual)
	if err != nil {
		log.Errorf("Failure decoding signature message: %v", err)
		return false
	}

	// check if same but differently formatted
	if reflect.DeepEqual(actual, expected) {
		return true
	}

	// element by element compare
	log.Debugf("Decoded signature message %v", actual)
	return check_match(actual, expected, "hash", true) &&
		check_match(actual, expected, "name", false) &&
		check_match(actual, expected, "size", false) &&
		check_match(actual, expected, "hash", false) &&
		check_match(actual, expected, "contents", false) &&
		check_match(actual, expected, "inputs", false)
}

func SignatureOriginMatch() bool {
	// TODO implement trace.Origin == signature.Origin
	return true
}

func SignatureTimestampMatch() bool {
	// TODO implement trace.RegistrationTime is within certificate.NotBefore+NotAfter
	return true
}

func RegisterTraces(traces []RegisterTrace, api *ClientWithResponses) error {

	res, err := api.PutTracesV1WithResponse(context.Background(), traces)
	if err != nil {
		return fmt.Errorf("unable to call API endpoint: %v", err)
	}

	registration := res.JSON201
	if registration != nil {
		log.Infof("Registered %v traces successfully.", registration.Success)
		if registration.Error > 0 {
			//TODO list all the failed traces here
			return fmt.Errorf("registration failed for %v traces", registration.Error)
		}
		return nil
	}
	return fmt.Errorf("invalid response from service: %s: %s", res.Status(), res.Body)
}
