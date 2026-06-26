// Package ca implements a dynamic in-memory certificate authority.
// It generates a self-signed root CA on startup and issues per-host
// leaf certificates on demand, caching them for reuse.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"time"
)

// CA is a dynamic certificate authority that issues leaf certs per host.
type CA struct {
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	tlsCert  tls.Certificate
	mu       sync.RWMutex
	cache    map[string]*tls.Certificate
	CertPool *x509.CertPool
}

// New creates a new in-memory CA with a freshly generated root certificate.
func New() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "tls-proxy Dynamic CA",
			Organization: []string{"tls-proxy"},
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        cert,
	}

	return &CA{
		cert:     cert,
		key:      key,
		tlsCert:  tlsCert,
		cache:    make(map[string]*tls.Certificate),
		CertPool: pool,
	}, nil
}

// CertPEM returns the root CA certificate as PEM-encoded bytes.
// Install this in the OS/browser trust store to avoid TLS warnings.
func (ca *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.cert.Raw,
	})
}

// IssueCert returns a TLS certificate for the given hostname, issuing
// one on demand and caching it for subsequent calls.
func (ca *CA) IssueCert(host string) (*tls.Certificate, error) {
	ca.mu.RLock()
	if cert, ok := ca.cache[host]; ok {
		ca.mu.RUnlock()
		return cert, nil
	}
	ca.mu.RUnlock()

	ca.mu.Lock()
	defer ca.mu.Unlock()

	// Double-check after acquiring write lock.
	if cert, ok := ca.cache[host]; ok {
		return cert, nil
	}

	cert, err := ca.issue(host)
	if err != nil {
		return nil, err
	}
	ca.cache[host] = cert
	return cert, nil
}

func (ca *CA) issue(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore: time.Now().Add(-5 * time.Minute),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER, ca.cert.Raw},
		PrivateKey:  key,
	}
	tlsCert.Leaf, err = x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return tlsCert, nil
}
