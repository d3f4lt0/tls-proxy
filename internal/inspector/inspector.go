// Package inspector captures and logs intercepted HTTP/HTTPS traffic.
package inspector

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Entry holds a single captured request/response pair.
type Entry struct {
	ID        uint64
	Timestamp time.Time
	Host      string
	Request   *http.Request
	Response  *http.Response
	ReqBody   []byte
	RespBody  []byte
	Duration  time.Duration
	TLS       bool
}

// Inspector captures and logs HTTP traffic.
type Inspector struct {
	counter  atomic.Uint64
	out      io.Writer
	Verbose  bool
	OnEntry  func(*Entry)
}

// New returns an Inspector that writes to w (os.Stdout if nil).
func New(w io.Writer, verbose bool) *Inspector {
	if w == nil {
		w = os.Stdout
	}
	return &Inspector{out: w, Verbose: verbose}
}

// Capture records the req/resp pair, draining and restoring both bodies.
func (ins *Inspector) Capture(req *http.Request, resp *http.Response, dur time.Duration, tls bool) *Entry {
	id := ins.counter.Add(1)

	var reqBody []byte
	if req.Body != nil && req.Body != http.NoBody {
		reqBody, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
	}

	var respBody []byte
	if resp.Body != nil {
		respBody, _ = io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewReader(respBody))
	}

	e := &Entry{
		ID:        id,
		Timestamp: time.Now(),
		Host:      req.Host,
		Request:   req,
		Response:  resp,
		ReqBody:   reqBody,
		RespBody:  respBody,
		Duration:  dur,
		TLS:       tls,
	}

	ins.print(e)

	if ins.OnEntry != nil {
		ins.OnEntry(e)
	}

	return e
}

func (ins *Inspector) print(e *Entry) {
	scheme := "http"
	if e.TLS {
		scheme = "https"
	}

	statusColor := colorForStatus(e.Response.StatusCode)
	const reset = "\033[0m"
	cyan := "\033[36m"
	dim := "\033[90m"

	line := fmt.Sprintf("\n%s[#%04d]%s %s %s%s%s %s  %s%d%s  %s\n",
		dim, e.ID, reset,
		timestamp(e.Timestamp),
		cyan, e.Request.Method, reset,
		scheme+"://"+e.Host+e.Request.URL.RequestURI(),
		statusColor, e.Response.StatusCode, reset,
		formatDur(e.Duration),
	)
	fmt.Fprint(ins.out, line)

	if ins.Verbose {
		dumpReq, _ := httputil.DumpRequest(e.Request, false)
		fmt.Fprintf(ins.out, "%s%s%s", "\033[90m", indent(string(dumpReq)), reset)
		if len(e.ReqBody) > 0 {
			fmt.Fprintf(ins.out, "  Body(%d): %s\n", len(e.ReqBody), truncate(e.ReqBody, 256))
		}
		dumpResp, _ := httputil.DumpResponse(e.Response, false)
		fmt.Fprintf(ins.out, "%s%s%s", "\033[90m", indent(string(dumpResp)), reset)
		if len(e.RespBody) > 0 {
			fmt.Fprintf(ins.out, "  Body(%d): %s\n", len(e.RespBody), truncate(e.RespBody, 256))
		}
	}
}

func colorForStatus(code int) string {
	switch {
	case code < 300:
		return "\033[32m" // green
	case code < 400:
		return "\033[33m" // yellow
	case code < 500:
		return "\033[31m" // red
	default:
		return "\033[35m" // magenta
	}
}

func timestamp(t time.Time) string {
	return t.Format("15:04:05.000")
}

func formatDur(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

func indent(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = "  " + l
	}
	return strings.Join(lines, "\n") + "\n"
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + fmt.Sprintf("…[+%d]", len(b)-n)
}
