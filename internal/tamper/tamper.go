// Package tamper provides a hook pipeline for modifying requests and responses
// in flight. Rules are matched by host glob and method, then applied in order.
package tamper

import (
	"bytes"
	"io"
	"net/http"
	"strings"
)

// RequestHook is a function that can modify an outbound request.
type RequestHook func(req *http.Request) error

// ResponseHook is a function that can modify an inbound response.
type ResponseHook func(resp *http.Response) error

// Rule pairs a matcher with optional request/response hooks.
type Rule struct {
	// HostGlob matches the request Host header. "*" matches everything.
	HostGlob string
	// Methods is the set of HTTP methods to match. Empty = all methods.
	Methods []string
	OnRequest  RequestHook
	OnResponse ResponseHook
}

// Engine runs a pipeline of tamper rules against intercepted traffic.
type Engine struct {
	rules []*Rule
}

// New returns an empty Engine.
func New() *Engine {
	return &Engine{}
}

// Add appends a rule to the pipeline.
func (e *Engine) Add(r *Rule) {
	e.rules = append(e.rules, r)
}

// ApplyRequest runs all matching request hooks.
func (e *Engine) ApplyRequest(req *http.Request) error {
	for _, r := range e.rules {
		if !r.matchHost(req.Host) || !r.matchMethod(req.Method) {
			continue
		}
		if r.OnRequest != nil {
			if err := r.OnRequest(req); err != nil {
				return err
			}
		}
	}
	return nil
}

// ApplyResponse runs all matching response hooks.
func (e *Engine) ApplyResponse(req *http.Request, resp *http.Response) error {
	for _, r := range e.rules {
		if !r.matchHost(req.Host) || !r.matchMethod(req.Method) {
			continue
		}
		if r.OnResponse != nil {
			if err := r.OnResponse(resp); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Rule) matchHost(host string) bool {
	if r.HostGlob == "" || r.HostGlob == "*" {
		return true
	}
	// Strip port for matching.
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return globMatch(r.HostGlob, host)
}

func (r *Rule) matchMethod(method string) bool {
	if len(r.Methods) == 0 {
		return true
	}
	for _, m := range r.Methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

// globMatch is a minimal glob: supports leading/trailing/single *.
func globMatch(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	parts := strings.SplitN(pattern, "*", 2)
	return strings.HasPrefix(s, parts[0]) && strings.HasSuffix(s, parts[1])
}

// --- Built-in helper rules ---

// AddRequestHeader returns a Rule that injects a header into every request.
func AddRequestHeader(host, key, value string) *Rule {
	return &Rule{
		HostGlob: host,
		OnRequest: func(req *http.Request) error {
			req.Header.Set(key, value)
			return nil
		},
	}
}

// AddResponseHeader returns a Rule that injects a header into every response.
func AddResponseHeader(host, key, value string) *Rule {
	return &Rule{
		HostGlob: host,
		OnResponse: func(resp *http.Response) error {
			resp.Header.Set(key, value)
			return nil
		},
	}
}

// ReplaceResponseBody returns a Rule that replaces matching bytes in response bodies.
func ReplaceResponseBody(host, old, new string) *Rule {
	return &Rule{
		HostGlob: host,
		OnResponse: func(resp *http.Response) error {
			if resp.Body == nil {
				return nil
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			body = bytes.ReplaceAll(body, []byte(old), []byte(new))
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			return nil
		},
	}
}
