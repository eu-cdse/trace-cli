// Package main provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.16.2 DO NOT EDIT.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/oapi-codegen/runtime"
)

const (
	HTTPBearerScopes = "HTTPBearer.Scopes"
)

// Defines values for ServerStatus.
const (
	Degraded ServerStatus = "degraded"
	Error    ServerStatus = "error"
	Running  ServerStatus = "running"
)

// Defines values for TraceEvent.
const (
	COPY     TraceEvent = "COPY"
	CREATE   TraceEvent = "CREATE"
	DELETE   TraceEvent = "DELETE"
	OBSOLETE TraceEvent = "OBSOLETE"
)

// Content A product's content contains the path and the filehash
type Content struct {
	Hash string `json:"hash"`
	Path string `json:"path"`
}

// HTTPValidationError defines model for HTTPValidationError.
type HTTPValidationError struct {
	Detail *[]ValidationError `json:"detail,omitempty"`
}

// Input The input product used to derive a product from.
type Input struct {
	Hash string `json:"hash"`
	Name string `json:"name"`
}

// Product A product is either a file itself, or a collection of files.
type Product struct {
	Contents *[]Content `json:"contents,omitempty"`
	Hash     string     `json:"hash"`
	Inputs   *[]Input   `json:"inputs,omitempty"`
	Name     string     `json:"name"`
	Size     int64      `json:"size"`
}

// RegisterTrace A trace describes a specific event for a product used for validate incoming traces.
type RegisterTrace struct {
	Event         TraceEvent `json:"event"`
	HashAlgorithm string     `json:"hash_algorithm"`
	Obsolescence  *string    `json:"obsolescence,omitempty"`
	Product       Product    `json:"product"`
	Signature     Signature  `json:"signature"`
}

// ServerInfo The information describing the state of the server.
type ServerInfo struct {
	ProtocolVersion []string `json:"protocol_version"`
	ServerVersion   string   `json:"server_version"`

	// Status The status of the server.
	Status ServerStatus `json:"status"`
}

// ServerStatus The status of the server.
type ServerStatus string

// Signature The trace signature can be used to verify a products integrity.
//
// The signature is created using an asymmetric, public-key encryption system.
// The bytes being signed correspond to the trace's product dictionary, in lower-case,
// compact JSON format (i.e. without whitespaces or linebreaks) and encoded in utf-8.
type Signature struct {
	Algorithm   string `json:"algorithm"`
	Certificate string `json:"certificate"`
	Message     string `json:"message"`
	Signature   string `json:"signature"`
}

// Trace A trace describes a specific event for a product at a specific origin with primary id.
type Trace struct {
	Event         TraceEvent `json:"event"`
	HashAlgorithm string     `json:"hash_algorithm"`
	Id            string     `json:"id"`
	Obsolescence  *string    `json:"obsolescence,omitempty"`
	Origin        string     `json:"origin"`
	Product       Product    `json:"product"`
	Signature     Signature  `json:"signature"`
	Timestamp     time.Time  `json:"timestamp"`
}

// TraceEvent A trace event describes how the trace comes into life.
//
// CREATE: A new product is generated.
// COPY: A product is copied to a new location.
// DELETE: A product is removed from a location.
// OBSOLETE: A product is no longer recommended for use.
type TraceEvent string

// TraceRegistration The results of a trace registration.
type TraceRegistration struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}

// TraceRegistrations defines model for TraceRegistrations.
type TraceRegistrations struct {
	Error   int                 `json:"error"`
	Success int                 `json:"success"`
	Traces  []TraceRegistration `json:"traces"`
}

// TraceValidation The results of a trace validation.
type TraceValidation struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}

// ValidationError defines model for ValidationError.
type ValidationError struct {
	Loc  []ValidationError_Loc_Item `json:"loc"`
	Msg  string                     `json:"msg"`
	Type string                     `json:"type"`
}

// ValidationErrorLoc0 defines model for .
type ValidationErrorLoc0 = string

// ValidationErrorLoc1 defines model for .
type ValidationErrorLoc1 = int

// ValidationError_Loc_Item defines model for ValidationError.loc.Item.
type ValidationError_Loc_Item struct {
	union json.RawMessage
}

// PutTracesV1JSONBody defines parameters for PutTracesV1.
type PutTracesV1JSONBody = []RegisterTrace

// ValidateProductParams defines parameters for ValidateProduct.
type ValidateProductParams struct {
	Filehash string `form:"filehash" json:"filehash"`
}

// PutTracesV1JSONRequestBody defines body for PutTracesV1 for application/json ContentType.
type PutTracesV1JSONRequestBody = PutTracesV1JSONBody

// AsValidationErrorLoc0 returns the union data inside the ValidationError_Loc_Item as a ValidationErrorLoc0
func (t ValidationError_Loc_Item) AsValidationErrorLoc0() (ValidationErrorLoc0, error) {
	var body ValidationErrorLoc0
	err := json.Unmarshal(t.union, &body)
	return body, err
}

// FromValidationErrorLoc0 overwrites any union data inside the ValidationError_Loc_Item as the provided ValidationErrorLoc0
func (t *ValidationError_Loc_Item) FromValidationErrorLoc0(v ValidationErrorLoc0) error {
	b, err := json.Marshal(v)
	t.union = b
	return err
}

// MergeValidationErrorLoc0 performs a merge with any union data inside the ValidationError_Loc_Item, using the provided ValidationErrorLoc0
func (t *ValidationError_Loc_Item) MergeValidationErrorLoc0(v ValidationErrorLoc0) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	merged, err := runtime.JsonMerge(t.union, b)
	t.union = merged
	return err
}

// AsValidationErrorLoc1 returns the union data inside the ValidationError_Loc_Item as a ValidationErrorLoc1
func (t ValidationError_Loc_Item) AsValidationErrorLoc1() (ValidationErrorLoc1, error) {
	var body ValidationErrorLoc1
	err := json.Unmarshal(t.union, &body)
	return body, err
}

// FromValidationErrorLoc1 overwrites any union data inside the ValidationError_Loc_Item as the provided ValidationErrorLoc1
func (t *ValidationError_Loc_Item) FromValidationErrorLoc1(v ValidationErrorLoc1) error {
	b, err := json.Marshal(v)
	t.union = b
	return err
}

// MergeValidationErrorLoc1 performs a merge with any union data inside the ValidationError_Loc_Item, using the provided ValidationErrorLoc1
func (t *ValidationError_Loc_Item) MergeValidationErrorLoc1(v ValidationErrorLoc1) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	merged, err := runtime.JsonMerge(t.union, b)
	t.union = merged
	return err
}

func (t ValidationError_Loc_Item) MarshalJSON() ([]byte, error) {
	b, err := t.union.MarshalJSON()
	return b, err
}

func (t *ValidationError_Loc_Item) UnmarshalJSON(b []byte) error {
	err := t.union.UnmarshalJSON(b)
	return err
}

// RequestEditorFn  is the function signature for the RequestEditor callback function
type RequestEditorFn func(ctx context.Context, req *http.Request) error

// Doer performs HTTP requests.
//
// The standard http.Client implements this interface.
type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client which conforms to the OpenAPI3 specification for this service.
type Client struct {
	// The endpoint of the server conforming to this interface, with scheme,
	// https://api.deepmap.com for example. This can contain a path relative
	// to the server, such as https://api.deepmap.com/dev-test, and all the
	// paths in the swagger spec will be appended to the server.
	Server string

	// Doer for performing requests, typically a *http.Client with any
	// customized settings, such as certificate chains.
	Client HttpRequestDoer

	// A list of callbacks for modifying requests which are generated before sending over
	// the network.
	RequestEditors []RequestEditorFn
}

// ClientOption allows setting custom parameters during construction
type ClientOption func(*Client) error

// Creates a new Client, with reasonable defaults
func NewClient(server string, opts ...ClientOption) (*Client, error) {
	// create a client with sane default values
	client := Client{
		Server: server,
	}
	// mutate client and add all optional params
	for _, o := range opts {
		if err := o(&client); err != nil {
			return nil, err
		}
	}
	// ensure the server URL always has a trailing slash
	if !strings.HasSuffix(client.Server, "/") {
		client.Server += "/"
	}
	// create httpClient, if not already present
	if client.Client == nil {
		client.Client = &http.Client{}
	}
	return &client, nil
}

// WithHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithHTTPClient(doer HttpRequestDoer) ClientOption {
	return func(c *Client) error {
		c.Client = doer
		return nil
	}
}

// WithRequestEditorFn allows setting up a callback function, which will be
// called right before sending the request. This can be used to mutate the request.
func WithRequestEditorFn(fn RequestEditorFn) ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, fn)
		return nil
	}
}

// The interface specification for the client above.
type ClientInterface interface {
	// PingStatusGet request
	PingStatusGet(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error)

	// PutTracesV1WithBody request with any body
	PutTracesV1WithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	PutTracesV1(ctx context.Context, body PutTracesV1JSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// SearchHashV1 request
	SearchHashV1(ctx context.Context, hash string, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetTraceByProductNameV1 request
	GetTraceByProductNameV1(ctx context.Context, productname string, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetTraceByIdV1 request
	GetTraceByIdV1(ctx context.Context, id string, reqEditors ...RequestEditorFn) (*http.Response, error)

	// ValidateProduct request
	ValidateProduct(ctx context.Context, productname string, params *ValidateProductParams, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) PingStatusGet(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPingStatusGetRequest(c.Server)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) PutTracesV1WithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPutTracesV1RequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) PutTracesV1(ctx context.Context, body PutTracesV1JSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPutTracesV1Request(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) SearchHashV1(ctx context.Context, hash string, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewSearchHashV1Request(c.Server, hash)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetTraceByProductNameV1(ctx context.Context, productname string, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetTraceByProductNameV1Request(c.Server, productname)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetTraceByIdV1(ctx context.Context, id string, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetTraceByIdV1Request(c.Server, id)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) ValidateProduct(ctx context.Context, productname string, params *ValidateProductParams, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewValidateProductRequest(c.Server, productname, params)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewPingStatusGetRequest generates requests for PingStatusGet
func NewPingStatusGetRequest(server string) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/status")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewPutTracesV1Request calls the generic PutTracesV1 builder with application/json body
func NewPutTracesV1Request(server string, body PutTracesV1JSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewPutTracesV1RequestWithBody(server, "application/json", bodyReader)
}

// NewPutTracesV1RequestWithBody generates requests for PutTracesV1 with any type of body
func NewPutTracesV1RequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/traces")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("PUT", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewSearchHashV1Request generates requests for SearchHashV1
func NewSearchHashV1Request(server string, hash string) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "hash", runtime.ParamLocationPath, hash)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/traces/hash/%s", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewGetTraceByProductNameV1Request generates requests for GetTraceByProductNameV1
func NewGetTraceByProductNameV1Request(server string, productname string) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "productname", runtime.ParamLocationPath, productname)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/traces/name/%s", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewGetTraceByIdV1Request generates requests for GetTraceByIdV1
func NewGetTraceByIdV1Request(server string, id string) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "id", runtime.ParamLocationPath, id)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/traces/%s", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewValidateProductRequest generates requests for ValidateProduct
func NewValidateProductRequest(server string, productname string, params *ValidateProductParams) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "productname", runtime.ParamLocationPath, productname)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v1/traces/%s/validate", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	if params != nil {
		queryValues := queryURL.Query()

		if queryFrag, err := runtime.StyleParamWithLocation("form", true, "filehash", runtime.ParamLocationQuery, params.Filehash); err != nil {
			return nil, err
		} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
			return nil, err
		} else {
			for k, v := range parsed {
				for _, v2 := range v {
					queryValues.Add(k, v2)
				}
			}
		}

		queryURL.RawQuery = queryValues.Encode()
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func (c *Client) applyEditors(ctx context.Context, req *http.Request, additionalEditors []RequestEditorFn) error {
	for _, r := range c.RequestEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	for _, r := range additionalEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// ClientWithResponses builds on ClientInterface to offer response payloads
type ClientWithResponses struct {
	ClientInterface
}

// NewClientWithResponses creates a new ClientWithResponses, which wraps
// Client with return type handling
func NewClientWithResponses(server string, opts ...ClientOption) (*ClientWithResponses, error) {
	client, err := NewClient(server, opts...)
	if err != nil {
		return nil, err
	}
	return &ClientWithResponses{client}, nil
}

// WithBaseURL overrides the baseURL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) error {
		newBaseURL, err := url.Parse(baseURL)
		if err != nil {
			return err
		}
		c.Server = newBaseURL.String()
		return nil
	}
}

// ClientWithResponsesInterface is the interface specification for the client with responses above.
type ClientWithResponsesInterface interface {
	// PingStatusGetWithResponse request
	PingStatusGetWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*PingStatusGetResponse, error)

	// PutTracesV1WithBodyWithResponse request with any body
	PutTracesV1WithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*PutTracesV1Response, error)

	PutTracesV1WithResponse(ctx context.Context, body PutTracesV1JSONRequestBody, reqEditors ...RequestEditorFn) (*PutTracesV1Response, error)

	// SearchHashV1WithResponse request
	SearchHashV1WithResponse(ctx context.Context, hash string, reqEditors ...RequestEditorFn) (*SearchHashV1Response, error)

	// GetTraceByProductNameV1WithResponse request
	GetTraceByProductNameV1WithResponse(ctx context.Context, productname string, reqEditors ...RequestEditorFn) (*GetTraceByProductNameV1Response, error)

	// GetTraceByIdV1WithResponse request
	GetTraceByIdV1WithResponse(ctx context.Context, id string, reqEditors ...RequestEditorFn) (*GetTraceByIdV1Response, error)

	// ValidateProductWithResponse request
	ValidateProductWithResponse(ctx context.Context, productname string, params *ValidateProductParams, reqEditors ...RequestEditorFn) (*ValidateProductResponse, error)
}

type PingStatusGetResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *ServerInfo
}

// Status returns HTTPResponse.Status
func (r PingStatusGetResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r PingStatusGetResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type PutTracesV1Response struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON201      *TraceRegistrations
}

// Status returns HTTPResponse.Status
func (r PutTracesV1Response) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r PutTracesV1Response) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type SearchHashV1Response struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *[]Trace
	JSON422      *HTTPValidationError
}

// Status returns HTTPResponse.Status
func (r SearchHashV1Response) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r SearchHashV1Response) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetTraceByProductNameV1Response struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *[]Trace
	JSON422      *HTTPValidationError
}

// Status returns HTTPResponse.Status
func (r GetTraceByProductNameV1Response) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetTraceByProductNameV1Response) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetTraceByIdV1Response struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *Trace
	JSON422      *HTTPValidationError
}

// Status returns HTTPResponse.Status
func (r GetTraceByIdV1Response) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetTraceByIdV1Response) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type ValidateProductResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *TraceValidation
	JSON422      *HTTPValidationError
}

// Status returns HTTPResponse.Status
func (r ValidateProductResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r ValidateProductResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// PingStatusGetWithResponse request returning *PingStatusGetResponse
func (c *ClientWithResponses) PingStatusGetWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*PingStatusGetResponse, error) {
	rsp, err := c.PingStatusGet(ctx, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParsePingStatusGetResponse(rsp)
}

// PutTracesV1WithBodyWithResponse request with arbitrary body returning *PutTracesV1Response
func (c *ClientWithResponses) PutTracesV1WithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*PutTracesV1Response, error) {
	rsp, err := c.PutTracesV1WithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParsePutTracesV1Response(rsp)
}

func (c *ClientWithResponses) PutTracesV1WithResponse(ctx context.Context, body PutTracesV1JSONRequestBody, reqEditors ...RequestEditorFn) (*PutTracesV1Response, error) {
	rsp, err := c.PutTracesV1(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParsePutTracesV1Response(rsp)
}

// SearchHashV1WithResponse request returning *SearchHashV1Response
func (c *ClientWithResponses) SearchHashV1WithResponse(ctx context.Context, hash string, reqEditors ...RequestEditorFn) (*SearchHashV1Response, error) {
	rsp, err := c.SearchHashV1(ctx, hash, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseSearchHashV1Response(rsp)
}

// GetTraceByProductNameV1WithResponse request returning *GetTraceByProductNameV1Response
func (c *ClientWithResponses) GetTraceByProductNameV1WithResponse(ctx context.Context, productname string, reqEditors ...RequestEditorFn) (*GetTraceByProductNameV1Response, error) {
	rsp, err := c.GetTraceByProductNameV1(ctx, productname, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetTraceByProductNameV1Response(rsp)
}

// GetTraceByIdV1WithResponse request returning *GetTraceByIdV1Response
func (c *ClientWithResponses) GetTraceByIdV1WithResponse(ctx context.Context, id string, reqEditors ...RequestEditorFn) (*GetTraceByIdV1Response, error) {
	rsp, err := c.GetTraceByIdV1(ctx, id, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetTraceByIdV1Response(rsp)
}

// ValidateProductWithResponse request returning *ValidateProductResponse
func (c *ClientWithResponses) ValidateProductWithResponse(ctx context.Context, productname string, params *ValidateProductParams, reqEditors ...RequestEditorFn) (*ValidateProductResponse, error) {
	rsp, err := c.ValidateProduct(ctx, productname, params, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseValidateProductResponse(rsp)
}

// ParsePingStatusGetResponse parses an HTTP response from a PingStatusGetWithResponse call
func ParsePingStatusGetResponse(rsp *http.Response) (*PingStatusGetResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &PingStatusGetResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest ServerInfo
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	}

	return response, nil
}

// ParsePutTracesV1Response parses an HTTP response from a PutTracesV1WithResponse call
func ParsePutTracesV1Response(rsp *http.Response) (*PutTracesV1Response, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &PutTracesV1Response{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 201:
		var dest TraceRegistrations
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON201 = &dest

	}

	return response, nil
}

// ParseSearchHashV1Response parses an HTTP response from a SearchHashV1WithResponse call
func ParseSearchHashV1Response(rsp *http.Response) (*SearchHashV1Response, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &SearchHashV1Response{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest []Trace
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 422:
		var dest HTTPValidationError
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON422 = &dest

	}

	return response, nil
}

// ParseGetTraceByProductNameV1Response parses an HTTP response from a GetTraceByProductNameV1WithResponse call
func ParseGetTraceByProductNameV1Response(rsp *http.Response) (*GetTraceByProductNameV1Response, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetTraceByProductNameV1Response{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest []Trace
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 422:
		var dest HTTPValidationError
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON422 = &dest

	}

	return response, nil
}

// ParseGetTraceByIdV1Response parses an HTTP response from a GetTraceByIdV1WithResponse call
func ParseGetTraceByIdV1Response(rsp *http.Response) (*GetTraceByIdV1Response, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetTraceByIdV1Response{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest Trace
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 422:
		var dest HTTPValidationError
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON422 = &dest

	}

	return response, nil
}

// ParseValidateProductResponse parses an HTTP response from a ValidateProductWithResponse call
func ParseValidateProductResponse(rsp *http.Response) (*ValidateProductResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &ValidateProductResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest TraceValidation
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 422:
		var dest HTTPValidationError
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON422 = &dest

	}

	return response, nil
}

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"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",
	"GO/f3v8nAAD//651f7GGMAAA",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	res := make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	resolvePath := PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		pathToFile := url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}
