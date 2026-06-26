package tamper

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestAddRequestHeader(t *testing.T) {
	e := New()
	e.Add(AddRequestHeader("*", "X-Test", "hello"))

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Host = "example.com"

	if err := e.ApplyRequest(req); err != nil {
		t.Fatal(err)
	}
	if v := req.Header.Get("X-Test"); v != "hello" {
		t.Fatalf("got %q want %q", v, "hello")
	}
}

func TestAddResponseHeader(t *testing.T) {
	e := New()
	e.Add(AddResponseHeader("example.com", "X-Proxy", "intercepted"))

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Host = "example.com"
	resp := &http.Response{
		Header: make(http.Header),
		Body:   http.NoBody,
	}

	if err := e.ApplyResponse(req, resp); err != nil {
		t.Fatal(err)
	}
	if v := resp.Header.Get("X-Proxy"); v != "intercepted" {
		t.Fatalf("got %q want %q", v, "intercepted")
	}
}

func TestReplaceResponseBody(t *testing.T) {
	e := New()
	e.Add(ReplaceResponseBody("*", "world", "proxy"))

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Host = "example.com"
	body := "hello world"
	resp := &http.Response{
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}

	if err := e.ApplyResponse(req, resp); err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if got := buf.String(); got != "hello proxy" {
		t.Fatalf("got %q want %q", got, "hello proxy")
	}
}

func TestHostGlobMatching(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		match   bool
	}{
		{"*", "anything.com", true},
		{"example.com", "example.com", true},
		{"example.com", "other.com", false},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", false},
	}
	for _, tc := range cases {
		r := &Rule{HostGlob: tc.pattern}
		got := r.matchHost(tc.host)
		if got != tc.match {
			t.Errorf("matchHost(%q, %q) = %v, want %v", tc.pattern, tc.host, got, tc.match)
		}
	}
}

func TestMethodFiltering(t *testing.T) {
	e := New()
	called := false
	e.Add(&Rule{
		HostGlob: "*",
		Methods:  []string{"POST"},
		OnRequest: func(req *http.Request) error {
			called = true
			return nil
		},
	})

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Host = "example.com"
	_ = e.ApplyRequest(req)
	if called {
		t.Fatal("rule should not fire for GET when Methods=[POST]")
	}

	req2, _ := http.NewRequest("POST", "http://example.com/", nil)
	req2.Host = "example.com"
	_ = e.ApplyRequest(req2)
	if !called {
		t.Fatal("rule should fire for POST")
	}
}
