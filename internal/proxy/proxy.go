// Package proxy implements the MITM proxy core.
// It handles:
//   - Plain HTTP requests (forwarded and optionally inspected)
//   - HTTPS CONNECT tunnels (intercepted: dynamic cert issued, traffic decrypted)
package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/d3f4lt0/tls-proxy/internal/ca"
	"github.com/d3f4lt0/tls-proxy/internal/inspector"
	"github.com/d3f4lt0/tls-proxy/internal/tamper"
)

// Config holds proxy startup options.
type Config struct {
	Addr        string // listen address, e.g. ":8080"
	CA          *ca.CA
	Inspector   *inspector.Inspector
	Tamper      *tamper.Engine
	Passthrough bool // if true, CONNECT tunnels are forwarded without interception
}

// Proxy is the MITM HTTP/HTTPS proxy server.
type Proxy struct {
	cfg    Config
	server *http.Server
}

// New creates a Proxy from cfg.
func New(cfg Config) *Proxy {
	p := &Proxy{cfg: cfg}
	p.server = &http.Server{
		Addr:         cfg.Addr,
		Handler:      http.HandlerFunc(p.ServeHTTP),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	return p
}

// ListenAndServe starts the proxy. It blocks until the server stops.
func (p *Proxy) ListenAndServe() error {
	fmt.Printf("  tls-proxy listening on %s\n", p.cfg.Addr)
	return p.server.ListenAndServe()
}

// ServeHTTP dispatches plain HTTP requests and CONNECT tunnels.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// handleHTTP forwards a plain HTTP request, capturing it if an Inspector is set.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	r.RequestURI = ""
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}

	if p.cfg.Tamper != nil {
		if err := p.cfg.Tamper.ApplyRequest(r); err != nil {
			http.Error(w, "tamper request error: "+err.Error(), http.StatusBadGateway)
			return
		}
	}

	start := time.Now()
	resp, err := http.DefaultTransport.RoundTrip(r)
	dur := time.Since(start)
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if p.cfg.Tamper != nil {
		_ = p.cfg.Tamper.ApplyResponse(r, resp)
	}

	if p.cfg.Inspector != nil {
		p.cfg.Inspector.Capture(r, resp, dur, false)
	}

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// handleConnect intercepts a CONNECT tunnel, decrypts TLS, and inspects traffic.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	// Acknowledge the CONNECT to the client.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "hijack failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	_, _ = fmt.Fprint(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	if p.cfg.Passthrough {
		p.tunnel(clientConn, r.Host)
		return
	}

	// Issue a leaf cert for this host and terminate TLS with the client.
	cert, err := p.cfg.CA.IssueCert(host)
	if err != nil {
		return
	}

	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	})
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		return
	}

	// Read decrypted HTTP requests from the client and forward upstream.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false}, //nolint:gosec
		DialContext:     nil,
	}

	br := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			break
		}
		req.URL.Scheme = "https"
		req.URL.Host = r.Host
		req.RequestURI = ""
		req.Host = r.Host

		if p.cfg.Tamper != nil {
			if err := p.cfg.Tamper.ApplyRequest(req); err != nil {
				break
			}
		}

		start := time.Now()
		resp, err := transport.RoundTrip(req)
		dur := time.Since(start)
		if err != nil {
			writeErrorResponse(tlsConn, err)
			break
		}

		if p.cfg.Tamper != nil {
			_ = p.cfg.Tamper.ApplyResponse(req, resp)
		}

		if p.cfg.Inspector != nil {
			p.cfg.Inspector.Capture(req, resp, dur, true)
		}

		if err := resp.Write(tlsConn); err != nil {
			resp.Body.Close()
			break
		}
		resp.Body.Close()
	}
}

// tunnel blindly forwards bytes between client and upstream (passthrough mode).
func (p *Proxy) tunnel(clientConn net.Conn, target string) {
	upstream, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, clientConn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(clientConn, upstream); done <- struct{}{} }()
	<-done
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func writeErrorResponse(conn net.Conn, err error) {
	resp := &http.Response{
		StatusCode: http.StatusBadGateway,
		ProtoMajor: 1, ProtoMinor: 1,
		Header: make(http.Header),
		Body:   io.NopCloser(io.MultiReader()),
	}
	resp.Header.Set("Content-Type", "text/plain")
	_ = resp.Write(conn)
	_ = httputil.NewChunkedWriter(conn)
}
