package ca

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestNew(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if c.cert == nil {
		t.Fatal("root cert is nil")
	}
	if !c.cert.IsCA {
		t.Fatal("root cert is not a CA")
	}
}

func TestIssueCert(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	hosts := []string{"example.com", "api.example.com", "192.168.1.1"}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			cert, err := c.IssueCert(host)
			if err != nil {
				t.Fatalf("IssueCert(%q) error: %v", host, err)
			}
			if cert == nil {
				t.Fatal("cert is nil")
			}
			if cert.Leaf == nil {
				t.Fatal("leaf is nil")
			}
		})
	}
}

func TestIssueCertCached(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	cert1, err := c.IssueCert("cache-test.com")
	if err != nil {
		t.Fatal(err)
	}
	cert2, err := c.IssueCert("cache-test.com")
	if err != nil {
		t.Fatal(err)
	}
	if cert1 != cert2 {
		t.Fatal("expected same pointer from cache")
	}
}

func TestCertPEM(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	pem := c.CertPEM()
	if len(pem) == 0 {
		t.Fatal("CertPEM returned empty")
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("AppendCertsFromPEM failed")
	}
}

func TestIssuedCertVerifiesAgainstCA(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}

	tlsCert, err := c.IssueCert("verify.example.com")
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	opts := x509.VerifyOptions{
		DNSName: "verify.example.com",
		Roots:   c.CertPool,
	}
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatalf("leaf cert verification failed: %v", err)
	}

	_ = tls.Certificate{}
}
